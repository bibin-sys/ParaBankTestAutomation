function Invoke-AwsCliJson {
    param(
        [Parameter(Mandatory = $true)]
        [string[]] $Arguments,
        [string]   $Profile
    )

    # Force JSON and disable pager so output is clean.
    $fullArgs = @('--output','json','--no-cli-pager')
    if ($Profile) { $fullArgs += @('--profile', $Profile) }
    $fullArgs += $Arguments

    # Capture only stdout on success; don't contaminate JSON with stderr.
    $stdout = & aws @fullArgs 2>$null
    $exit   = $LASTEXITCODE

    if ($exit -ne 0) {
        # Get stderr for a helpful error message
        $stderr = & aws @fullArgs 1>$null 2>&1
        throw "AWS CLI command failed ($exit): aws $($fullArgs -join ' ')`n$stderr"
    }

    # PS 5.1 returns string[]; join into one JSON string.
    $jsonText = ($stdout -join "`n")

    try {
        return $jsonText | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "Unable to parse AWS CLI response as JSON: aws $($fullArgs -join ' ')`n$jsonText"
    }
}
