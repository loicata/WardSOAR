$source = Get-Content 'F:\Documents\loicata\WardSOAR\scripts\build.ps1' -Raw
$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors) {
    foreach ($e in $errors) {
        Write-Host ("Line {0} Col {1}: {2}" -f $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
        Write-Host ("  near: " + $e.Extent.Text)
    }
} else {
    Write-Host "CLEAN"
}
