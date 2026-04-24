# WardSOAR - EVE JSON streaming from pfSense
# Streams new lines from the remote EVE JSON file via SSH tail -f
# Appends to the local file without overwriting

$SSH_KEY = 'C:\Users\loica\.ssh\ward_key'
$PFSENSE = 'admin@192.168.2.1'
$REMOTE_EVE = '/var/log/suricata/suricata_igc252678/eve.json'

# Auto-detect local EVE path: installed location or dev location
$INSTALLED_EVE = 'C:\Program Files\WardSOAR\data\eve.json'
$DEV_EVE = 'F:\Documents\loicata\WardSOAR\data\eve.json'

if (Test-Path (Split-Path $INSTALLED_EVE)) {
    $LOCAL_EVE = $INSTALLED_EVE
} else {
    $LOCAL_EVE = $DEV_EVE
}

Write-Host 'WardSOAR EVE Stream - Starting'
Write-Host "  Remote: ${PFSENSE}:${REMOTE_EVE}"
Write-Host "  Local:  ${LOCAL_EVE}"
Write-Host '  Press Ctrl+C to stop'
Write-Host ''

# Stream new lines via SSH tail -f and append to local file
& ssh -i $SSH_KEY -o 'StrictHostKeyChecking=no' $PFSENSE "tail -n 0 -f $REMOTE_EVE" | ForEach-Object {
    $_ | Out-File -FilePath $LOCAL_EVE -Append -Encoding utf8
    $time = Get-Date -Format 'HH:mm:ss'
    Write-Host "$time $_"
}
