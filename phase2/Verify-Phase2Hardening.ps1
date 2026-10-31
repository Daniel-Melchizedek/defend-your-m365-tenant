#Requires -Version 7.2
[CmdletBinding()]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [string] $OutputDirectory = (Join-Path $PSScriptRoot 'reports'),
    [switch] $DeviceCode,
    [switch] $SkipTeams,
    [switch] $SsprAllScopeConfirmed,
    [switch] $FailOnGap
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Phase2.Common.psm1') -Force
$config = Read-Phase2Config $ConfigPath
$operator = Connect-Phase2Graph -Config $config -DeviceCode:$DeviceCode
$snapshot = Get-Phase2Snapshot -Config $config -SkipTeams:$SkipTeams -DeviceCode:$DeviceCode
$results = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param([string] $Name, [scriptblock] $Check)
    try { $result = & $Check }
    catch { $result = @{ Status = 'UNKNOWN'; Evidence = $_.Exception.Message } }
    $results.Add([pscustomobject]@{ Control = $Name; Status = $result.Status; Evidence = $result.Evidence })
}

Add-Check 'ConditionalAccessMigrationGate' {
    $defaults = Get-Phase2Data $snapshot 'SecurityDefaults'
    if ($defaults.isEnabled -eq $true) {
        @{ Status = 'BLOCKED'; Evidence = 'Security Defaults remains enabled. An approved tenant-wide replacement baseline is required before CA deployment.' }
    }
    elseif ($defaults.isEnabled -eq $false) {
        @{ Status = 'UNKNOWN'; Evidence = 'Security Defaults is disabled. Verify enforced tenant-wide replacement coverage; this is not authorization to deploy.' }
    }
    else { throw 'Security Defaults state was not returned.' }
}
Add-Check 'PilotReadiness' {
    $pilots = @(Resolve-Phase2Users $snapshot $config.PilotUpns)
    Assert-Phase2Readiness -Snapshot $snapshot -Users $pilots -Registration
    @{ Status = 'IMPLEMENTED'; Evidence = 'Pilot P2 entitlement and reported MFA/SSPR capability verified. Phishing-resistant authentication still requires a live test.' }
}
foreach ($key in @('PhishingResistantMfa', 'BlockLegacy', 'SignInRisk', 'UserRisk')) {
    Add-Check $key { Get-Phase2CaAssessment -Config $config -Snapshot $snapshot -Key $key }
}
Add-Check 'EmergencyAccessConfiguration' {
    $null = Assert-Phase2EmergencyAccess -Config $config -Snapshot $snapshot
    @{ Status = 'IMPLEMENTED'; Evidence = 'Nominated accounts are enabled cloud-only members with permanent active Global Administrator. Password custody, independent phishing-resistant methods and live sign-in are NOT verified.' }
}
Add-Check 'DisableUserConsent' {
    $policy = Get-Phase2Data $snapshot 'Authorization'
    if (-not $policy.defaultUserRolePermissions.ContainsKey('permissionGrantPoliciesAssigned')) { throw 'Consent assignments were not returned.' }
    $remaining = @($policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    if ($remaining.Count) { @{ Status = 'NOT-CONFIGURED'; Evidence = 'Ordinary-user self-consent assignments remain.' } }
    else { @{ Status = 'IMPLEMENTED'; Evidence = 'No ordinary-user self-consent assignments. Existing grants and administrator consent permissions are unaffected.' } }
}
Add-Check 'AdminConsentWorkflow' {
    $expected = Get-Phase2ConsentBody $config $snapshot
    $actual = Get-Phase2Data $snapshot 'Consent'
    if (Test-Phase2ConsentShape -Actual $actual -Expected $expected) {
        @{ Status = 'IMPLEMENTED'; Evidence = 'Workflow enabled with both nominated reviewers, email reminders and notifications. Weekly review and approval authority must be tested operationally.' }
    }
    else { @{ Status = 'NOT-CONFIGURED'; Evidence = 'Admin consent workflow differs from the two-reviewer configuration.' } }
}
Add-Check 'TeamsMeetingPolicies' {
    $policies = @(Get-Phase2Data $snapshot 'Teams')
    if (-not $policies.Count -or -not @($policies | Where-Object { $_.Identity -eq 'Global' }).Count) { throw 'Teams Global policy was not returned.' }
    $gaps = @($policies | Where-Object { -not (Test-Phase2TeamsPolicy $_) })
    if (-not $gaps.Count) { @{ Status = 'IMPLEMENTED'; Evidence = 'Global and all returned named policies have the three intended settings. Organizer overrides, policy propagation and live guest access still require testing.' } }
    elseif (@($policies | Where-Object { $_.Identity -eq "Tag:$($config.TeamsPilotPolicyName)" -and (Test-Phase2TeamsPolicy $_) }).Count) {
        @{ Status = 'STAGED'; Evidence = "Pilot policy exists; $($gaps.Count) policies still differ. This does not verify assignment to pilot users." }
    }
    else { @{ Status = 'NOT-CONFIGURED'; Evidence = "Policies missing one or more controls: $($gaps.Identity -join ', ')." } }
}
Add-Check 'TeamsPilotAssignment' {
    $policies = @(Get-Phase2Data $snapshot 'Teams')
    $pilotPolicy = @($policies | Where-Object { ($_.Identity -replace '^Tag:', '') -eq $config.TeamsPilotPolicyName })
    if ($pilotPolicy.Count -ne 1 -or -not (Test-Phase2TeamsPolicy $pilotPolicy[0])) {
        throw 'Expected pilot policy settings were not verified.'
    }
    if (-not $config.PilotUpns.Count) { throw 'No pilots are configured.' }
    foreach ($upn in $config.PilotUpns) {
        $assignments = @(Get-CsUserPolicyAssignment -Identity $upn -PolicyType TeamsMeetingPolicy -ErrorAction Stop)
        $snapshot.Data["TeamsAssignment:$upn"] = $assignments
        if ($assignments.Count -ne 1 -or ($assignments[0].PolicyName -replace '^Tag:', '') -ne $config.TeamsPilotPolicyName) {
            throw "Expected effective Teams policy was not verified for $upn. Check propagation and assignment precedence."
        }
    }
    @{ Status = 'STAGED'; Evidence = 'Configured pilots have the expected effective meeting policy and settings. Live meeting tests and tenant-wide rollout remain pending.' }
}
Add-Check 'PimJustInTimeRoles' { Get-Phase2PimAssessment $config $snapshot }
Add-Check 'MemberReadiness' {
    $users = @(Get-Phase2Data $snapshot 'Users' | Where-Object {
        $_.accountEnabled -eq $true -and $_.userType -eq 'Member' -and $_.userPrincipalName -notin $config.EmergencyUpns
    })
    Assert-Phase2Readiness -Snapshot $snapshot -Users $users -Registration
    @{ Status = 'IMPLEMENTED'; Evidence = 'Enabled non-emergency members have reported P2, MFA and SSPR capability. Phishing-resistant sign-in, guests, hybrid writeback and service-account dependencies need separate testing.' }
}
Add-Check 'SsprAllScope' {
    if ($SsprAllScopeConfirmed) { @{ Status = 'IMPLEMENTED'; Evidence = 'Operator explicitly confirmed Entra Password reset > Properties = All; not a Graph-derived scope check.' } }
    else { @{ Status = 'UNKNOWN'; Evidence = 'Confirm SSPR All in Entra; the exact scope is not exposed by the supported Graph getter. No default attestation is assumed.' } }
}
Add-Check 'LegacySignInReview' {
    $signIns = @(Get-Phase2Data $snapshot 'SignIns')
    $legacy = @($signIns | Where-Object { $_.clientAppUsed -and $_.clientAppUsed -notin @('Browser', 'Mobile Apps and Desktop clients') })
    @{ Status = 'UNKNOWN'; Evidence = "$($legacy.Count) potentially legacy records in the last seven days, out of $($signIns.Count) available sign-ins. Review evidence and longer-cycle devices; absence is not proof of dependency migration." }
}

$report = @{
    TenantId = $config.TenantId; Operator = $operator.userPrincipalName; CheckedAt = $snapshot.CheckedAt
    Results = @($results); Snapshot = $snapshot
    Limitations = 'Read-only configuration evidence, not a Secure Score total or proof of effective sign-in/meeting behavior. Registration can lag 36 hours. Read failures are UNKNOWN.'
}
$path = Save-Phase2Evidence -Directory $OutputDirectory -Label 'validation' -Value $report
$results | Format-Table Control,Status,Evidence -Wrap
Write-Host "Evidence: $path"
if ($FailOnGap -and @($results | Where-Object { $_.Status -ne 'IMPLEMENTED' }).Count) {
    throw "Validation contains staged, missing or unverified controls. See $path"
}