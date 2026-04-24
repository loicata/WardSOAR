# Netgate 4200 bootstrap — step-by-step guide

> Source of truth for the **Bootstrap checklist** card in the WardSOAR
> Netgate tab. Walk through it once per appliance — new or factory-reset.

---

## When to follow this guide

| Situation | Use this guide? |
|---|:---:|
| Brand-new Netgate 4200 out of the box | Yes, all 11 steps |
| Factory-reset Netgate 4200 | Yes, but steps 1 (firmware/licence parts) can be skipped |
| Already-configured Netgate, WardSOAR reinstalled | No — the Audit + Establish baseline alone suffice |
| pfSense Plus upgrade without factory reset | No — no state changes on the Netgate side |

### New vs reset — what really differs

The bootstrap path is the same except for the first block:

- **New appliance**: you must run the factory wizard, upgrade the firmware,
  activate the pfSense Plus licence, and register the box under your
  Netgate account. All of this happens once, out of the box.
- **Factory-reset appliance**: the firmware is still current, the Plus
  licence is bound to the hardware TPM (it survives the reset), and your
  Netgate account still knows the serial. You still have to:
  - reset the admin password (reset drops it to `admin` / `pfsense`),
  - rebuild LAN / WAN / DNS (`config.xml` is wiped),
  - re-enable SSH and re-deposit `ward_key.pub` (authorized_keys are gone),
  - reinstall the Suricata package (packages are wiped).

After a reset, also run the **Post-reset cleanup** card in the Netgate tab
of WardSOAR. It purges the tamper baseline (every surface has legitimately
changed), the block tracker (the pf blocklist table is empty), and the
trusted-temp registry (quarantine rules are gone).

---

## The 12 steps

The UI checklist uses the same numbering.

### 1. Install Sysmon with network logging (PC)

**What**: install Microsoft Sysinternals Sysmon on this PC with a config
that logs every network connection (Event ID 3). Without Sysmon,
WardSOAR can only attribute Suricata alerts to a local Windows process
when the socket is still open at the moment of the capture — UDP bursts
and already-closed TCP flows end up with "unknown process". Sysmon adds
persistent, retroactive process attribution: the Image path, PID and
ProcessGuid are written to the Windows Event Log and survive the socket
lifetime.

**Where**: elevated PowerShell on the WardSOAR PC.

1. Download Sysmon from
   [learn.microsoft.com/sysinternals/downloads/sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon).
2. Download the config from
   [github.com/SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
   (`sysmonconfig-export.xml`). This config already has Event ID 3
   (NetworkConnect) enabled and excludes high-volume noise like
   `svchost.exe` → Microsoft endpoints.
3. From an elevated PowerShell:

   ```powershell
   Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
   Expand-Archive Sysmon.zip
   Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmonconfig-export.xml
   .\Sysmon\Sysmon64.exe -accepteula -i .\sysmonconfig-export.xml
   ```

4. Confirm the service is running:

   ```powershell
   Get-Service Sysmon64
   ```

   Status should be `Running`. WardSOAR's Netgate tab shows a banner
   under the Bootstrap checklist when Sysmon is missing or stopped, so
   you will see confirmation on the next relaunch.

### 2. Finish the Netgate wizard

**What**: factory wizard, firmware upgrade, pfSense Plus licence activation.
**Where**: pfSense webGUI, accessed via the default LAN IP.

1. Connect a laptop to LAN.
2. Open `https://192.168.1.1` (default) in a browser. Accept the
   self-signed certificate.
3. Sign in with `admin` / `pfsense`. Change the password as soon as
   prompted.
4. The wizard walks you through hostname, timezone, DNS servers,
   LAN / WAN addressing.
5. Accept the firmware upgrade when offered — it may take 10 minutes
   and a reboot.
6. Sign in to your Netgate account (`https://portal.netgate.com`) and
   link the appliance. The Plus licence activates automatically.

Tick step 1 in the WardSOAR checklist once the webGUI is reachable with
your configured LAN address.

### 3. Enable SSH and install `ward_key.pub`

**What**: authenticate WardSOAR as the `admin` user over SSH.
**Where**: System → Advanced → Admin Access → Secure Shell.

1. Tick **Enable Secure Shell**.
2. Set **SSHd Authentication Method** to **Public Key Only**.
3. Set **SSH port** to `22` (or whatever you configured in
   `config.yaml` under `responder.pfsense.ssh_port`).
4. Save.
5. Go to System → User Manager → `admin` (edit).
6. Paste the full content of `ward_key.pub` into **Authorized SSH Keys**.
7. Save.

Sanity check from the Windows host:

```powershell
ssh -i "$env:APPDATA\WardSOAR\ward_key" admin@192.168.2.1 "pfctl -s info"
```

You should see pf status. If you get a host key prompt, accept it;
WardSOAR itself does not verify host keys yet (a latent but known
MitM exposure on the LAN — tracked for Phase 9).

### 4. Install the Suricata package

**What**: install Suricata via pfSense's Package Manager.
**Where**: System → Package Manager → Available Packages.

1. Type `suricata` in the search box.
2. Click **+ Install** next to the package.
3. Confirm. The install takes 1-2 minutes on a 4200; the page shows
   progress logs.
4. When it finishes, a new **Services → Suricata** entry appears in
   the menu.

WardSOAR **cannot** automate this step: the Package Manager has its
own session handling, logging and rollback logic that is too risky to
drive via SSH.

### 5. Attach Suricata to `PORT2LAN`

**What**: create the Suricata instance that monitors the LAN segment.
**Where**: Services → Suricata → Interfaces → **+ Add**.

1. **Interface**: `PORT2LAN (igc2)`.
2. **Description**: `igc2 suricata`.
3. **Send Alerts to System Log**: tick.
4. **Detection profile**: High (or Medium if you need to lower CPU).
5. Leave defaults on Stream, Flow, IP, Protocol Settings.
6. Save — the instance is created but stopped.

### 6. Enable EVE JSON output

**What**: stream structured events so WardSOAR can tail them over SSH.
**Where**: Services → Suricata → `igc2` (edit) → **Logs Mgmt** tab.

1. **EVE JSON Log**: Enabled.
2. Tick every event type WardSOAR uses: Alerts, HTTP, DNS, TLS, DHCP,
   SMTP, SSH, Files, Flow, Drop.
3. **TLS Log**: Enabled (extra context on TLS handshakes).
4. **PCAP Log Alerts Only**: Enabled (disk-friendly).
5. **Stats collection**: Enabled.
6. Save.
7. Note the EVE JSON path under the logs directory — typically
   `/var/log/suricata/suricata_igc2<id>/eve.json`. Paste it into
   `config.yaml` under `watcher.ssh.remote_eve_path`.

### 7. Create the `WardSOAR_LAN_protect` and `WardSOAR_noise_filter` lists

**What**: keep known-legitimate traffic silent.
**Where**: Services → Suricata → Pass Lists / Suppress Lists.

**Pass list — `WardSOAR_LAN_protect`**:
- Include the LAN / VLAN subnets, LAN gateways, DNS servers, any VIPs,
  and any VPN tunnel endpoints.
- Suricata never evaluates alerts whose source or destination falls in
  a Pass list.

**Suppress list — `WardSOAR_noise_filter`**:
- Start with the SIDs already calibrated on this site:
  - `2031071` — ET INFO Observed DNS Query to .top TLD
  - `2013504` — ET POLICY GNU/Linux APT User-Agent
  - `2062715` — ET INFO HTTP OAuth 1.0 Request
- Add more as you observe recurrent false positives.

Then go back to **Interfaces → `igc2` → WAN Settings**. Bind the two
lists to the interface (Pass List and Suppress List drop-downs). Save.

### 8. Run the WardSOAR Audit

**What**: let WardSOAR read the live Netgate state over SSH and list
anything still missing.
**Where**: WardSOAR → Netgate tab → **Run Check** (primary button).

The audit never mutates anything. Expect findings like:

- `suricata.process_running` — **critical**, Suricata is installed but
  not started. Will be addressed in step 8.
- `suricata.rules_loaded` — **critical**, rule set not yet downloaded.
  Step 8.
- `pf.blocklist_table` — **critical**, the table WardSOAR uses to drop
  malicious IPs does not exist yet. Step 8.

### 9. Apply the 5 SSH-only fixes

**What**: WardSOAR applies the handlers backed by a registered apply
function and a post-apply verification.

1. Tick every critical finding in the audit result.
2. Click **Apply selected**.

Behind the scenes:

- `suricata.rules_loaded` — runs the pfSense rule updater.
- `suricata.process_running` — starts the Suricata service.
- `pf.blocklist_table` — creates the ephemeral pf blocklist table.
- `pf.alias_persistent` — migrates the blocklist from Host alias to
  urltable so the entries survive a reboot.
- `suricata.runmode` — switches Suricata to `workers` runmode (better
  throughput on multi-core pfSense).

Each handler backs up `config.xml` before touching it; a post-apply
verification either confirms the change or rolls back from the backup.

### 10. Deploy `wardsoar_custom.rules`

**What**: ship WardSOAR's custom Suricata rules tailored to your
threat model.
**Where**: Netgate tab → Custom rules card → **Deploy to Netgate**.

The rules file is generated from `config/known_bad_actors.yaml` plus
three hand-written Ben-pattern signatures. It is written to
`/usr/local/etc/suricata/rules/wardsoar_custom.rules` over SSH.

Use **Preview rules** first if you want to review the file content
before it hits the Netgate — the preview renders the generated
content in a dialog without writing anything.

### 11. Activate `wardsoar_custom.rules` in pfSense Categories

**What**: flip pfSense's switch to actually load the custom rules.
**Where**: Services → Suricata → `igc2` → **Categories** tab.

1. Under **Custom rules files**, tick `wardsoar_custom.rules`.
2. Save.
3. Restart Suricata (top-right button on the Interfaces list).

This is the sole clic WardSOAR cannot replace: the Categories tab
stores its state in `config.xml` and the rules file the pfSense
Suricata package reads depends on that flag being set.

### 12. Establish the tamper baseline

**What**: snapshot the legitimate Netgate state so any later drift is
detected.
**Where**: Netgate tab → Integrity card → **Establish baseline**.

WardSOAR captures a hash fingerprint of each integrity-sensitive
surface: authorised SSH keys, user accounts, `config.xml`, pf
ruleset, cron jobs, host keys, package list, kernel modules.

From then on, **Check for tampering** diffs the current state against
this baseline and flags any mismatch. When you intentionally change
the Netgate later (new SSH key, new package, new firewall rule),
click **Re-bless baseline** to commit the new state as ground truth.

Do not establish the baseline *before* steps 1–10 are complete, or
every later action will fire false tamper alerts.

---

## After the checklist

You are now ready to switch WardSOAR from `monitor` to `protect` mode.
Do so only after watching the Decision log for a day or two to confirm
no legitimate traffic gets flagged.

If you later need to factory-reset the Netgate, come back to this guide
and also click **Post-reset cleanup** in the Netgate tab before running
the checklist again — that drops the now-stale baseline, block tracker,
and trusted-temp entries.

---

## Known limitations

- **Step 3 (package install)** cannot be automated. The pfSense Package
  Manager has its own session and rollback logic; driving it via SSH
  risks leaving the box in a half-installed state.
- **Steps 4, 5, 6, 10** are UI-only clicks for now. Automating them would
  require editing `config.xml` over SSH plus a full pfSense reload — a
  non-trivial and risky chantier tracked under Phase 7b.2. The four
  clicks take five minutes, which rarely justifies the engineering.
- **SSH host key verification** is currently disabled (`known_hosts=None`
  in `pfsense_ssh.py`, `ssh_streamer.py`, `watcher.py`). A rogue host on
  the LAN could impersonate the Netgate. Tracked for Phase 9. Until
  then, keep WardSOAR on a trusted LAN.
