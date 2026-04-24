; WardSOAR Installer — Inno Setup Script
; Builds a setup wizard with custom configuration pages

#define MyAppName "WardSOAR"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "Loic Ader"
#define MyAppURL "https://loicata.com"
#define MyAppExeName "WardSOAR.exe"

[Setup]
AppId={{7B3F8A2E-5C4D-4E6F-9A1B-2D3E4F5A6B7C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=..\build\installer
OutputBaseFilename=WardSOAR_Setup_{#MyAppVersion}
SetupIconFile=assets\ward.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "startup"; Description: "Start {#MyAppName} when Windows starts"; GroupDescription: "Windows startup:"

[Files]
; PyInstaller output
Source: "..\dist\WardSOAR\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Default config files (preserve on upgrade)
Source: "..\config\whitelist.yaml"; DestDir: "{app}\config"; Flags: onlyifdoesntexist
Source: "..\config\known_false_positives.yaml"; DestDir: "{app}\config"; Flags: onlyifdoesntexist
Source: "..\config\network_baseline.yaml"; DestDir: "{app}\config"; Flags: onlyifdoesntexist

; Templates (extracted at install time by Pascal code)
Source: "config_template.yaml"; Flags: dontcopy
Source: "env_template.txt"; Flags: dontcopy

; Log access script
Source: "..\scripts\grant_log_access.bat"; DestDir: "{app}\scripts"

[Dirs]
Name: "{app}\data"; Permissions: users-modify
Name: "{app}\data\logs"; Permissions: users-modify
Name: "{app}\snapshots"; Permissions: users-modify
Name: "{app}\config"; Permissions: users-modify
Name: "{app}\config\prompts"; Permissions: users-modify

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#MyAppName}"; ValueData: """{app}\{#MyAppExeName}"""; Flags: uninsdeletevalue; Tasks: startup

[Run]
; Grant read access to Sysmon and Security event logs (requires admin — installer already elevated)
Filename: "cmd.exe"; Parameters: "/c ""{app}\scripts\grant_log_access.bat"""; Flags: runhidden; StatusMsg: "Granting event log access for forensics..."
; Restrict .env file permissions (only current user)
Filename: "cmd.exe"; Parameters: "/c icacls ""{app}\.env"" /inheritance:r /grant:r ""%USERNAME%:F"""; Flags: runhidden; StatusMsg: "Securing API keys file..."
; Optionally launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{app}\data\logs\*.log"
Type: filesandordirs; Name: "{app}\__pycache__"
Type: files; Name: "{app}\.env"

[Code]
var
  // Page 1: API Keys & pfSense SSH
  APIKeysPage: TWizardPage;
  AnthropicKeyEdit: TPasswordEdit;
  PfSenseSSHUserEdit: TEdit;
  PfSenseSSHKeyEdit: TEdit;
  PfSenseSSHPortEdit: TEdit;
  VirusTotalKeyEdit: TPasswordEdit;

  // Page 2: Network
  NetworkPage: TWizardPage;
  PfSenseIPEdit: TEdit;
  PCIPEdit: TEdit;
  DNS1Edit: TEdit;
  DNS2Edit: TEdit;
  EvePathEdit: TEdit;
  RemoteEvePathEdit: TEdit;

  // Page 3: Notifications (optional)
  NotifyPage: TWizardPage;
  SMTPUserEdit: TEdit;
  SMTPPassEdit: TPasswordEdit;
  TelegramTokenEdit: TPasswordEdit;

function CreateLabel(Page: TWizardPage; const Caption: string; Top: Integer): TLabel;
begin
  Result := TLabel.Create(Page);
  Result.Parent := Page.Surface;
  Result.Caption := Caption;
  Result.Top := Top;
  Result.Left := 0;
  Result.Width := Page.SurfaceWidth;
end;

function CreateEdit(Page: TWizardPage; Top: Integer; const Default: string): TEdit;
begin
  Result := TEdit.Create(Page);
  Result.Parent := Page.Surface;
  Result.Top := Top;
  Result.Left := 0;
  Result.Width := Page.SurfaceWidth;
  Result.Text := Default;
end;

function CreatePasswordEdit(Page: TWizardPage; Top: Integer): TPasswordEdit;
begin
  Result := TPasswordEdit.Create(Page);
  Result.Parent := Page.Surface;
  Result.Top := Top;
  Result.Left := 0;
  Result.Width := Page.SurfaceWidth;
  Result.Text := '';
end;

procedure InitializeWizard();
var
  Y: Integer;
begin
  // ========== PAGE 1: API KEYS ==========
  APIKeysPage := CreateCustomPage(wpSelectTasks,
    'API Keys Configuration',
    'Enter your API keys for WardSOAR services.');

  Y := 0;
  CreateLabel(APIKeysPage, 'Claude API Key (required — starts with sk-ant-):', Y);
  AnthropicKeyEdit := CreatePasswordEdit(APIKeysPage, Y + 22);

  Y := Y + 56;
  CreateLabel(APIKeysPage, 'pfSense SSH user:', Y);
  PfSenseSSHUserEdit := CreateEdit(APIKeysPage, Y + 22, 'admin');

  Y := Y + 56;
  CreateLabel(APIKeysPage, 'pfSense SSH private key path:', Y);
  PfSenseSSHKeyEdit := CreateEdit(APIKeysPage, Y + 22, 'C:\Users\' + GetUserNameString + '\.ssh\ward_key');

  Y := Y + 56;
  CreateLabel(APIKeysPage, 'pfSense SSH port:', Y);
  PfSenseSSHPortEdit := CreateEdit(APIKeysPage, Y + 22, '22');

  Y := Y + 56;
  CreateLabel(APIKeysPage, 'VirusTotal API Key (optional):', Y);
  VirusTotalKeyEdit := CreatePasswordEdit(APIKeysPage, Y + 22);

  // ========== PAGE 2: NETWORK ==========
  NetworkPage := CreateCustomPage(APIKeysPage.ID,
    'Network Configuration',
    'Configure your network settings for alert monitoring.');

  Y := 0;
  CreateLabel(NetworkPage, 'pfSense IP address:', Y);
  PfSenseIPEdit := CreateEdit(NetworkPage, Y + 22, '192.168.2.1');

  Y := Y + 56;
  CreateLabel(NetworkPage, 'This PC IP address:', Y);
  PCIPEdit := CreateEdit(NetworkPage, Y + 22, '192.168.2.100');

  Y := Y + 56;
  CreateLabel(NetworkPage, 'Primary DNS server:', Y);
  DNS1Edit := CreateEdit(NetworkPage, Y + 22, '1.1.1.1');

  Y := Y + 56;
  CreateLabel(NetworkPage, 'Secondary DNS server:', Y);
  DNS2Edit := CreateEdit(NetworkPage, Y + 22, '8.8.8.8');

  Y := Y + 56;
  CreateLabel(NetworkPage, 'EVE JSON local path (file mode fallback):', Y);
  EvePathEdit := CreateEdit(NetworkPage, Y + 22, 'C:\Program Files\WardSOAR\data\eve.json');

  Y := Y + 56;
  CreateLabel(NetworkPage, 'Remote EVE path on pfSense:', Y);
  RemoteEvePathEdit := CreateEdit(NetworkPage, Y + 22, '/var/log/suricata/suricata_igc252678/eve.json');

  // ========== PAGE 3: NOTIFICATIONS ==========
  NotifyPage := CreateCustomPage(NetworkPage.ID,
    'Notifications (Optional)',
    'Configure email and Telegram notifications. Leave blank to skip.');

  Y := 0;
  CreateLabel(NotifyPage, 'SMTP Username (email notifications):', Y);
  SMTPUserEdit := CreateEdit(NotifyPage, Y + 22, '');

  Y := Y + 56;
  CreateLabel(NotifyPage, 'SMTP Password:', Y);
  SMTPPassEdit := CreatePasswordEdit(NotifyPage, Y + 22);

  Y := Y + 56;
  CreateLabel(NotifyPage, 'Telegram Bot Token:', Y);
  TelegramTokenEdit := CreatePasswordEdit(NotifyPage, Y + 22);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if CurPageID = APIKeysPage.ID then
  begin
    // Validate Anthropic key
    if Trim(AnthropicKeyEdit.Text) = '' then
    begin
      MsgBox('Anthropic API Key is required. Get one at console.anthropic.com', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Pos('sk-ant-', AnthropicKeyEdit.Text) <> 1 then
    begin
      MsgBox('Anthropic API Key should start with "sk-ant-". Please check your key.', mbError, MB_OK);
      Result := False;
      Exit;
    end;

    // Validate pfSense SSH key path
    if not FileExists(PfSenseSSHKeyEdit.Text) then
    begin
      if MsgBox('SSH key file not found: ' + PfSenseSSHKeyEdit.Text + #13#10 +
                'Continue anyway? (You can configure it later)', mbConfirmation, MB_YESNO) = IDNO then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;

  if CurPageID = NetworkPage.ID then
  begin
    if Trim(PfSenseIPEdit.Text) = '' then
    begin
      MsgBox('pfSense IP address is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Trim(PCIPEdit.Text) = '' then
    begin
      MsgBox('PC IP address is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if Trim(EvePathEdit.Text) = '' then
    begin
      MsgBox('EVE JSON file path is required.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
  end;
end;

function ComputeSubnet(const IP: string): string;
var
  DotPos1, DotPos2, DotPos3: Integer;
begin
  // Extract first 3 octets and append .0/24
  DotPos1 := Pos('.', IP);
  if DotPos1 = 0 then begin Result := '192.168.2.0/24'; Exit; end;

  DotPos2 := Pos('.', Copy(IP, DotPos1 + 1, Length(IP)));
  if DotPos2 = 0 then begin Result := '192.168.2.0/24'; Exit; end;
  DotPos2 := DotPos1 + DotPos2;

  DotPos3 := Pos('.', Copy(IP, DotPos2 + 1, Length(IP)));
  if DotPos3 = 0 then begin Result := '192.168.2.0/24'; Exit; end;
  DotPos3 := DotPos2 + DotPos3;

  Result := Copy(IP, 1, DotPos3) + '0/24';
end;

function EscapeBackslashes(const S: string): string;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
end;

procedure GenerateConfigFiles();
var
  ConfigTemplate, EnvTemplate: AnsiString;
  ConfigContent, EnvContent: string;
  InstallDir, Subnet, EvePathEscaped: string;
begin
  // Load templates
  ExtractTemporaryFile('config_template.yaml');
  ExtractTemporaryFile('env_template.txt');

  if not LoadStringFromFile(ExpandConstant('{tmp}\config_template.yaml'), ConfigTemplate) then
  begin
    MsgBox('Failed to load config template.', mbError, MB_OK);
    Exit;
  end;
  if not LoadStringFromFile(ExpandConstant('{tmp}\env_template.txt'), EnvTemplate) then
  begin
    MsgBox('Failed to load env template.', mbError, MB_OK);
    Exit;
  end;

  ConfigContent := String(ConfigTemplate);
  EnvContent := String(EnvTemplate);

  // Compute derived values
  InstallDir := EscapeBackslashes(ExpandConstant('{app}'));
  Subnet := ComputeSubnet(PCIPEdit.Text);
  EvePathEscaped := EscapeBackslashes(EvePathEdit.Text);

  // Replace config placeholders
  StringChangeEx(ConfigContent, '{{PFSENSE_IP}}', PfSenseIPEdit.Text, True);
  StringChangeEx(ConfigContent, '{{PC_IP}}', PCIPEdit.Text, True);
  StringChangeEx(ConfigContent, '{{LAN_SUBNET}}', Subnet, True);
  StringChangeEx(ConfigContent, '{{DNS_1}}', DNS1Edit.Text, True);
  StringChangeEx(ConfigContent, '{{DNS_2}}', DNS2Edit.Text, True);
  StringChangeEx(ConfigContent, '{{EVE_JSON_PATH}}', EvePathEscaped, True);
  StringChangeEx(ConfigContent, '{{REMOTE_EVE_PATH}}', RemoteEvePathEdit.Text, True);
  StringChangeEx(ConfigContent, '{{INSTALL_DIR}}', InstallDir, True);

  // Replace env placeholders
  StringChangeEx(EnvContent, '{{ANTHROPIC_API_KEY}}', AnthropicKeyEdit.Text, True);
  StringChangeEx(EnvContent, '{{VIRUSTOTAL_API_KEY}}', VirusTotalKeyEdit.Text, True);
  StringChangeEx(EnvContent, '{{SMTP_USER}}', SMTPUserEdit.Text, True);
  StringChangeEx(EnvContent, '{{SMTP_PASSWORD}}', SMTPPassEdit.Text, True);
  StringChangeEx(EnvContent, '{{TELEGRAM_BOT_TOKEN}}', TelegramTokenEdit.Text, True);

  // Replace pfSense SSH placeholders in config
  StringChangeEx(ConfigContent, '{{PFSENSE_SSH_USER}}', PfSenseSSHUserEdit.Text, True);
  StringChangeEx(ConfigContent, '{{PFSENSE_SSH_KEY}}', EscapeBackslashes(PfSenseSSHKeyEdit.Text), True);
  StringChangeEx(ConfigContent, '{{PFSENSE_SSH_PORT}}', PfSenseSSHPortEdit.Text, True);

  // Write config.yaml (only if not exists — preserve user edits on upgrade)
  if not FileExists(ExpandConstant('{app}\config\config.yaml')) then
    SaveStringToFile(ExpandConstant('{app}\config\config.yaml'), AnsiString(ConfigContent), False);

  // Always write .env (contains secrets that may have changed)
  SaveStringToFile(ExpandConstant('{app}\.env'), AnsiString(EnvContent), False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    GenerateConfigFiles();
  end;
end;

// Update EVE path default when install dir changes
procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = NetworkPage.ID then
  begin
    if Pos('Program Files\WardSOAR', EvePathEdit.Text) > 0 then
      EvePathEdit.Text := ExpandConstant('{app}') + '\data\eve.json';
  end;
end;
