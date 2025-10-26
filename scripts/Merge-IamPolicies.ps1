[CmdletBinding(DefaultParameterSetName='Files')]
param(
    [Parameter(ParameterSetName='Arns', Mandatory=$true)]
    [string[]]$PolicyArns,

    [Parameter(ParameterSetName='Files', Mandatory=$true)]
    [string[]]$PolicyFiles,

    [Parameter()]
    [string]$OutputPath = './merged-policy.json',

    [Parameter()]
    [string]$AwsProfile
)

$ErrorActionPreference = 'Stop'

function Invoke-AwsCliJson {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$Arguments,

        [string]$Profile
    )

    $fullArgs = @()
    if ($Profile) {
        $fullArgs += '--profile'
        $fullArgs += $Profile
    }
    $fullArgs += $Arguments

    $commandLine = "aws $($fullArgs -join ' ')"
    Write-Verbose "Running: $commandLine"
    $result = & aws @fullArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "AWS CLI command failed ($LASTEXITCODE): $commandLine`n$result"
    }

    try {
        return $result | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "Unable to parse AWS CLI response as JSON: $commandLine`n$result"
    }
}

function ConvertFrom-PolicyDocumentString {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Document
    )

    try {
        return $Document | ConvertFrom-Json -Depth 100
    }
    catch {
        # Fall through to URL decoding
    }

    $decoded = [System.Net.WebUtility]::UrlDecode($Document)
    try {
        return $decoded | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "Failed to parse policy document JSON. Raw document:`n$decoded"
    }
}

function ConvertTo-NormalizedArray {
    param([object]$Value)

    if ($null -eq $Value) {
        return @()
    }

    $items = @()

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        foreach ($entry in $Value) {
            $items += $entry
        }
    }
    else {
        $items += $Value
    }

    $filtered = $items | Where-Object { $_ -ne $null -and $_ -ne '' }
    return $filtered
}

function ConvertTo-CanonicalStructure {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Collections.IDictionary]) {
        $ordered = [ordered]@{}
        foreach ($key in ($Value.Keys | Sort-Object)) {
            $ordered[$key] = ConvertTo-CanonicalStructure -Value $Value[$key]
        }
        return $ordered
    }

    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $ordered = [ordered]@{}
        foreach ($prop in ($Value.PSObject.Properties.Name | Sort-Object)) {
            $ordered[$prop] = ConvertTo-CanonicalStructure -Value $Value.$prop
        }
        return $ordered
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $list = @()
        foreach ($item in $Value) {
            $canonicalItem = ConvertTo-CanonicalStructure -Value $item
            $list += ,$canonicalItem
        }

        if ($list.Count -le 1) {
            return $list
        }

        $withKeys = foreach ($entry in $list) {
            $key = ($entry | ConvertTo-Json -Depth 100 -Compress)
            [pscustomobject]@{ Key = $key; Value = $entry }
        }

        return ($withKeys | Sort-Object Key | ForEach-Object { $_.Value })
    }

    return $Value
}

function Get-CanonicalJson {
    param([object]$Value)

    if ($null -eq $Value) { return '' }
    $ordered = ConvertTo-CanonicalStructure -Value $Value
    return ($ordered | ConvertTo-Json -Depth 100 -Compress)
}

function Normalize-Statement {
    param([object]$Statement)

    $clone = $Statement | ConvertTo-Json -Depth 100 | ConvertFrom-Json -Depth 100

    foreach ($property in 'Action','NotAction','Resource','NotResource') {
        if ($clone.PSObject.Properties.Name -contains $property) {
            $normalized = ConvertTo-NormalizedArray -Value $clone.$property
            $clone.PSObject.Properties.Remove($property)
            $clone | Add-Member -MemberType NoteProperty -Name $property -Value $normalized
        }
    }

    return $clone
}

function New-StatementGroup {
    param(
        [object]$Statement,
        [string]$ActionSide,
        [string]$ResourceSide,
        [string]$ConditionKey,
        [object]$OriginalCondition,
        [string]$ResourceKey
    )

    $group = [ordered]@{
        Effect         = $Statement.Effect
        ActionSide     = $ActionSide
        ResourceSide   = $ResourceSide
        ResourceKey    = $ResourceKey
        HasCondition   = $null -ne $OriginalCondition
        Condition      = $OriginalCondition
        ConditionKey   = $ConditionKey
        SidCandidates  = New-Object System.Collections.Generic.List[string]
    }

    $group.ActionValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $group.ResourceValues = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    if ($ActionSide) {
        foreach ($value in $Statement.$ActionSide) {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                [void]$group.ActionValues.Add([string]$value)
            }
        }
    }

    if ($ResourceSide) {
        foreach ($value in $Statement.$ResourceSide) {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                [void]$group.ResourceValues.Add([string]$value)
            }
        }
    }

    if ($Statement.PSObject.Properties.Name -contains 'Sid' -and -not [string]::IsNullOrWhiteSpace($Statement.Sid)) {
        $group.SidCandidates.Add($Statement.Sid) | Out-Null
    }

    return $group
}

function Merge-StatementIntoGroup {
    param(
        [hashtable]$Group,
        [object]$Statement,
        [string]$ActionSide,
        [string]$ResourceSide,
        [string]$ResourceKey
    )

    if ($ResourceSide -and $Group.ResourceKey -ne $ResourceKey) {
        throw "Internal error: attempted to merge statements with different resource sets into the same group."
    }

    if ($ActionSide) {
        $incomingValues = @()
        foreach ($value in $Statement.$ActionSide) {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $incomingValues += [string]$value
            }
        }
        $Group.ActionValues.UnionWith([string[]]$incomingValues)
    }

    if ($ResourceSide) {
        $incomingResources = @()
        foreach ($value in $Statement.$ResourceSide) {
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                $incomingResources += [string]$value
            }
        }
        $Group.ResourceValues.UnionWith([string[]]$incomingResources)
    }

    if ($Statement.PSObject.Properties.Name -contains 'Sid' -and -not [string]::IsNullOrWhiteSpace($Statement.Sid)) {
        $Group.SidCandidates.Add($Statement.Sid) | Out-Null
    }
}

function Assign-UniqueSid {
    param(
        [string]$PreferredSid,
        [hashtable]$SidUsage,
        [ref]$AutoSidCounter
    )

    $baseSid = $PreferredSid
    if ([string]::IsNullOrWhiteSpace($baseSid)) {
        $baseSid = "AutoSid_$($AutoSidCounter.Value)"
        $AutoSidCounter.Value++
    }

    if (-not $SidUsage.ContainsKey($baseSid)) {
        $SidUsage[$baseSid] = 1
        return $baseSid
    }

    $index = $SidUsage[$baseSid]
    $candidate = "${baseSid}_$index"
    while ($SidUsage.ContainsKey($candidate)) {
        $index++
        $candidate = "${baseSid}_$index"
    }

    $SidUsage[$baseSid] = $index + 1
    $SidUsage[$candidate] = 1
    return $candidate
}

try {
    $documents = @()

    switch ($PSCmdlet.ParameterSetName) {
        'Arns' {
            foreach ($arn in $PolicyArns) {
                Write-Host "Fetching policy document for $arn"
                $policy = Invoke-AwsCliJson -Arguments @('iam','get-policy','--policy-arn',$arn) -Profile $AwsProfile
                $defaultVersionId = $policy.Policy.DefaultVersionId
                $version = Invoke-AwsCliJson -Arguments @('iam','get-policy-version','--policy-arn',$arn,'--version-id',$defaultVersionId) -Profile $AwsProfile
                $documents += ConvertFrom-PolicyDocumentString -Document $version.PolicyVersion.Document
            }
        }
        'Files' {
            foreach ($file in $PolicyFiles) {
                if (-not (Test-Path -LiteralPath $file)) {
                    throw "Policy file not found: $file"
                }

                Write-Host "Loading policy document from $file"
                $raw = Get-Content -LiteralPath $file -Raw
                $parsed = $null
                try {
                    $parsed = $raw | ConvertFrom-Json -Depth 100
                }
                catch {
                    # Fall through to URL decoding
                }

                if ($null -ne $parsed) {
                    $documents += $parsed
                }
                else {
                    $documents += ConvertFrom-PolicyDocumentString -Document $raw
                }
            }
        }
    }

    $groups = [ordered]@{}

    foreach ($doc in $documents) {
        if (-not $doc -or -not ($doc.PSObject.Properties.Name -contains 'Statement')) { continue }

        $statements = @($doc.Statement)
        foreach ($statement in $statements) {
            if (-not $statement) { continue }
            if ($statement.PSObject.Properties.Name -contains 'Principal') {
                $sidLabel = if ($statement.PSObject.Properties.Name -contains 'Sid') { $statement.Sid } else { '[no Sid]' }
                Write-Warning "Skipping trust policy statement (contains Principal): $sidLabel"
                continue
            }

            if (-not ($statement.PSObject.Properties.Name -contains 'Effect')) {
                $sidLabel = if ($statement.PSObject.Properties.Name -contains 'Sid') { $statement.Sid } else { '[no Sid]' }
                Write-Warning "Skipping statement without Effect: $sidLabel"
                continue
            }

            $hasAction = $statement.PSObject.Properties.Name -contains 'Action'
            $hasNotAction = $statement.PSObject.Properties.Name -contains 'NotAction'
            if ($hasAction -and $hasNotAction) {
                $sidLabel = if ($statement.PSObject.Properties.Name -contains 'Sid') { $statement.Sid } else { '[no Sid]' }
                Write-Warning "Skipping statement with both Action and NotAction: $sidLabel"
                continue
            }
            if (-not $hasAction -and -not $hasNotAction) {
                Write-Warning 'Skipping statement without Action or NotAction.'
                continue
            }

            $hasResource = $statement.PSObject.Properties.Name -contains 'Resource'
            $hasNotResource = $statement.PSObject.Properties.Name -contains 'NotResource'
            if ($hasResource -and $hasNotResource) {
                Write-Warning 'Skipping statement with both Resource and NotResource.'
                continue
            }

            $originalCondition = if ($statement.PSObject.Properties.Name -contains 'Condition') { $statement.Condition } else { $null }
            $normalized = Normalize-Statement -Statement $statement

            $actionSide = if ($normalized.PSObject.Properties.Name -contains 'NotAction') { 'NotAction' } elseif ($normalized.PSObject.Properties.Name -contains 'Action') { 'Action' } else { '' }
            $resourceSide = if ($normalized.PSObject.Properties.Name -contains 'NotResource') { 'NotResource' } elseif ($normalized.PSObject.Properties.Name -contains 'Resource') { 'Resource' } else { '' }
            if (-not $resourceSide) {
                $resourceSide = 'Resource'
                $normalized | Add-Member -NotePropertyName 'Resource' -NotePropertyValue @('*') -Force
            }
            $conditionKey = if ($null -ne $originalCondition) { Get-CanonicalJson -Value $originalCondition } else { '' }
            $resourceKey = if ($resourceSide) { Get-CanonicalJson -Value $normalized.$resourceSide } else { '' }

            $groupKey = "$($normalized.Effect)|$actionSide|$resourceSide|$conditionKey|$resourceKey"

            if (-not $groups.Contains($groupKey)) {
                $groups[$groupKey] = New-StatementGroup -Statement $normalized -ActionSide $actionSide -ResourceSide $resourceSide -ConditionKey $conditionKey -OriginalCondition $originalCondition -ResourceKey $resourceKey
            }
            else {
                Merge-StatementIntoGroup -Group $groups[$groupKey] -Statement $normalized -ActionSide $actionSide -ResourceSide $resourceSide -ResourceKey $resourceKey
            }
        }
    }

    $sidUsage = @{}
    $autoSidCounter = [ref]1
    $finalStatements = @()

    foreach ($group in $groups.GetEnumerator()) {
        $g = $group.Value
        $preferredSid = $null
        if ($g.SidCandidates.Count -gt 0) {
            $preferredSid = (@($g.SidCandidates | Sort-Object))[0]
        }

        $finalSid = Assign-UniqueSid -PreferredSid $preferredSid -SidUsage $sidUsage -AutoSidCounter $autoSidCounter
        $statement = [ordered]@{
            Sid    = $finalSid
            Effect = $g.Effect
        }

        switch ($g.ActionSide) {
            'Action'    {
                $sortedActions = @($g.ActionValues | Sort-Object -CaseSensitive)
                if ($sortedActions.Count -gt 0) {
                    $statement.Action = [string[]]$sortedActions
                }
            }
            'NotAction' {
                $sortedNotActions = @($g.ActionValues | Sort-Object -CaseSensitive)
                if ($sortedNotActions.Count -gt 0) {
                    $statement.NotAction = [string[]]$sortedNotActions
                }
            }
        }

        switch ($g.ResourceSide) {
            'Resource'    {
                $sortedResources = @($g.ResourceValues | Sort-Object -CaseSensitive)
                if ($sortedResources.Count -gt 0) {
                    $statement.Resource = [string[]]$sortedResources
                }
            }
            'NotResource' {
                $sortedNotResources = @($g.ResourceValues | Sort-Object -CaseSensitive)
                if ($sortedNotResources.Count -gt 0) {
                    $statement.NotResource = [string[]]$sortedNotResources
                }
            }
        }

        if ($g.HasCondition) {
            $statement.Condition = $g.Condition
        }

        $hasActs = ($g.ActionSide -eq 'Action'    -and $g.ActionValues.Count -gt 0)
        $hasNAct = ($g.ActionSide -eq 'NotAction' -and $g.ActionValues.Count -gt 0)
        if (-not ($hasActs -or $hasNAct)) { continue }

        $finalStatements += [pscustomobject]$statement
    }

    $mergedPolicy = [ordered]@{
        Version   = '2012-10-17'
        Statement = $finalStatements
    }

    $mergedJson = $mergedPolicy | ConvertTo-Json -Depth 50
    $byteCount = [System.Text.Encoding]::UTF8.GetByteCount($mergedJson)

    $resolvedPath = Resolve-Path -LiteralPath $OutputPath -ErrorAction SilentlyContinue
    if ($null -eq $resolvedPath) {
        $directory = Split-Path -Parent $OutputPath
        if ([string]::IsNullOrWhiteSpace($directory)) {
            $directory = (Get-Location).Path
        }

        if (-not (Test-Path -LiteralPath $directory)) {
            Write-Verbose "Creating directory $directory"
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }

        if ([System.IO.Path]::IsPathRooted($OutputPath)) {
            $fullPath = [System.IO.Path]::GetFullPath($OutputPath)
        }
        else {
            $fullPath = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $OutputPath))
        }
    }
    else {
        $fullPath = $resolvedPath.Path
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fullPath, $mergedJson, $utf8NoBom)
    Write-Host "Merged policy written to $fullPath"

    if ($byteCount -ge 6000) {
        Write-Warning "Merged policy size ${byteCount}B is close to the AWS managed policy limit (6144 bytes)."
    }

    try {
        $null = Get-Content -LiteralPath $fullPath -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        throw "Merged policy is not valid JSON: $($_.Exception.Message)"
    }

    if (Get-Command aws -ErrorAction SilentlyContinue) {
        try {
            Write-Host "Validating merged policy with aws iam validate-policy"
            $stdoutFile = [System.IO.Path]::GetTempFileName()
            $stderrFile = [System.IO.Path]::GetTempFileName()
            $validateArgs = @()
            if ($AwsProfile) {
                $validateArgs += '--profile'
                $validateArgs += $AwsProfile
            }
            $validateArgs += @('iam','validate-policy','--policy-document',"file://$fullPath")
            & aws @validateArgs 1> $stdoutFile 2> $stderrFile

            if (Test-Path -LiteralPath $stdoutFile) {
                $stdoutContent = Get-Content -LiteralPath $stdoutFile -Raw
                if (-not [string]::IsNullOrWhiteSpace($stdoutContent)) {
                    Write-Host "aws iam validate-policy output:`n$stdoutContent"
                }
            }

            if (Test-Path -LiteralPath $stderrFile) {
                $stderrContent = Get-Content -LiteralPath $stderrFile -Raw
                if (-not [string]::IsNullOrWhiteSpace($stderrContent)) {
                    Write-Warning "aws iam validate-policy errors:`n$stderrContent"
                }
            }

            Remove-Item -LiteralPath $stdoutFile,$stderrFile -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "aws iam validate-policy reported an issue or could not be executed: $($_.Exception.Message)"
        }
    }
    else {
        Write-Verbose 'AWS CLI not available for validate-policy check.'
    }

    Write-Host "Statements: $($finalStatements.Count); Size: ${byteCount}B"
}
catch {
    Write-Error $_
    exit 1
}
