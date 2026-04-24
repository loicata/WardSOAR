$errors = $null
$tokens = $null
[System.Management.Automation.Language.Parser]::ParseFile('F:\Documents\loicata\WardSOAR\scripts\build.ps1', [ref]$tokens, [ref]$errors) | Out-Null
if ($errors) {
    Write-Host "PARSE ERRORS:"
    foreach ($e in $errors) {
        Write-Host ("Line {0}, Col {1}: {2}" -f $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message)
    }
} else {
    Write-Host "OK - no parse errors"
}
