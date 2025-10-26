function Invoke-AwsCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,
        [string]   $Profile
    )

    $fullArgs = @('--output','json','--no-cli-pager')
    if ($Profile) { $fullArgs += @('--profile', $Profile) }
    $fullArgs += $Arguments
    $argLine = ($fullArgs -join ' ')

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'aws'
    $psi.Arguments = $argLine
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.StandardOutputEncoding = [System.Text.Encoding]::UTF8
    $psi.StandardErrorEncoding  = [System.Text.Encoding]::UTF8

    $p = [System.Diagnostics.Process]::Start($psi)
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    if ($p.ExitCode -ne 0) {
        throw "AWS CLI command failed ($($p.ExitCode)): aws $argLine`n$stderr"
    }

    $jsonText = $stdout.Trim() -replace '^\uFEFF',''    # strip a BOM just in case
    try {
        return $jsonText | ConvertFrom-Json -Depth 100
    } catch {
        throw "Unable to parse AWS CLI response as JSON: aws $argLine`n$jsonText"
    }
}
