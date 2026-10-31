#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [string] $OutputDirectory = (Join-Path $PSScriptRoot 'reports'),
    [ValidateSet('Consent', 'ConditionalAccessPilot', 'TeamsPilot')]
    [ValidateNotNullOrEmpty()] [string[]] $Action = @('ConditionalAccessPilot', 'TeamsPilot', 'Consent'),
    [switch] $Apply,
    [switch] $DeviceCode,
    [switch] $EmergencyAccessTested
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Phase2.Common.psm1') -Force
$config = Read-Phase2Config $ConfigPath
$scopes = @()
if ($Apply -and -not $WhatIfPreference -and 'Consent' -in $Action) {
    $scopes += @('Policy.ReadWrite.Authorization', 'Policy.ReadWrite.ConsentRequest')
}
if ($Apply -and -not $WhatIfPreference -and 'ConditionalAccessPilot' -in $Action) {
    $scopes += 'Policy.ReadWrite.ConditionalAccess'
}
$operator = Connect-Phase2Graph -Config $config -WriteScopes $scopes -DeviceCode:$DeviceCode
$results = [System.Collections.Generic.List[object]]::new()

foreach ($step in @($Action | Select-Object -Unique)) {
    $beforeFile = $null
    try {
        switch ($step) {
            'ConditionalAccessPilot' {
                $defaults = Invoke-Phase2Graph '/policies/identitySecurityDefaultsEnforcementPolicy'
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'ca-defaults' -Value @{
                    TenantId = $config.TenantId; SecurityDefaults = $defaults; EmergencyAccessTested = [bool]$EmergencyAccessTested
                }
                if ($defaults.isEnabled -ne $false) {
                    $results.Add(@{ Action = $step; Status = 'BLOCKED'; Evidence = $beforeFile
                        Note = 'Security Defaults is enabled or unknown. An approved tenant-wide replacement plan is required; defaults were not changed.' })
                    continue
                }
                if (-not $config.PilotUpns.Count) { throw 'At least one nominated pilot is required.' }
                $snapshot = @{ Data = @{}; Errors = @{} }
                foreach ($entry in @{
                    Users = '/users?$select=id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,assignedPlans'
                    Roles = '/roleManagement/directory/roleDefinitions'
                    ActiveSchedules = '/roleManagement/directory/roleAssignmentScheduleInstances'
                    Skus = '/subscribedSkus'
                    Strengths = '/identity/conditionalAccess/authenticationStrength/policies'
                    Policies = '/identity/conditionalAccess/policies'
                }.GetEnumerator()) { $snapshot.Data[$entry.Key] = @(Get-Phase2Collection $entry.Value) }
                $emergency = @(Assert-Phase2EmergencyAccess -Config $config -Snapshot $snapshot)
                $pilots = @(Resolve-Phase2Users $snapshot $config.PilotUpns)
                Assert-Phase2Readiness -Snapshot $snapshot -Users $pilots
                $strength = @($snapshot.Data.Strengths | Where-Object {
                    $_.id -eq '00000000-0000-0000-0000-000000000004' -and $_.policyType -eq 'builtIn'
                })
                if ($strength.Count -ne 1) { throw 'Built-in phishing-resistant authentication strength was not verified.' }
                $definitions = @(Get-Phase2CaDefinitions -IncludedUserIds $pilots.id -EmergencyUserIds $emergency.id -StrengthId $strength[0].id)
                $pending = [System.Collections.Generic.List[object]]::new()
                foreach ($definition in $definitions) {
                    $existing = @($snapshot.Data.Policies | Where-Object { $_.displayName -eq $definition.Body.displayName })
                    if ($existing.Count -gt 1) { throw "Duplicate policy names: $($definition.Body.displayName). No policies were changed." }
                    if ($existing.Count -eq 1) {
                        if (-not (Test-Phase2CaShape $existing[0] $definition.Body) -or
                            $existing[0].state -ne 'enabledForReportingButNotEnforced') {
                            throw "Existing policy differs or is enforced: $($definition.Body.displayName). It will not be overwritten."
                        }
                    }
                    else { $pending.Add($definition) }
                }
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'ca-before' -Value @{
                    TenantId = $config.TenantId; Snapshot = $snapshot; Definitions = $definitions
                    EmergencyAccessTested = [bool]$EmergencyAccessTested
                }
                if ($Apply -and -not $EmergencyAccessTested) { throw 'Confirm live emergency-account sign-in tests with -EmergencyAccessTested.' }
                if ($Apply -and $PSCmdlet.ShouldProcess(($config.PilotUpns -join ', '), 'Create missing report-only Conditional Access pilot policies')) {
                    foreach ($definition in $pending) {
                        $created = Invoke-Phase2Graph -Path '/identity/conditionalAccess/policies' -Method POST -Body $definition.Body
                        $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'ca-created' -Value @{
                            TenantId = $config.TenantId; BeforeFile = $beforeFile; Key = $definition.Key; Policy = $created
                        }
                        if (-not $created.id) { throw 'Policy creation returned no ID; reconcile live state before retrying.' }
                        $verified = Invoke-Phase2Graph "/identity/conditionalAccess/policies/$($created.id)"
                        if ($verified.state -ne 'enabledForReportingButNotEnforced' -or -not (Test-Phase2CaShape $verified $definition.Body)) {
                            throw 'Created policy failed read-back verification; inspect receipts before retrying.'
                        }
                    }
                    $afterFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'ca-after' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; Policies = @(Get-Phase2Collection '/identity/conditionalAccess/policies')
                    }
                    $results.Add(@{ Action = $step; Status = 'STAGED'; Evidence = $afterFile; Note = 'Pilot only, report-only. No policy enforcement or tenant-wide rollout.' })
                }
                else { $results.Add(@{ Action = $step; Status = 'PLANNED'; Evidence = $beforeFile }) }
            }
            'TeamsPilot' {
                if ($config.PilotUpns.Count -ne 1) { throw 'This Teams pilot requires exactly one nominated user to preserve their current policy baseline.' }
                if ($config.TeamsPilotPolicyName -notmatch '^Phase2-[a-zA-Z0-9-]+$') { throw 'Use a distinct Phase2- prefixed Teams pilot policy name.' }
                $upn = $config.PilotUpns[0]
                $user = Invoke-Phase2Graph ('/users/' + [uri]::EscapeDataString($upn) + '?$select=id,userPrincipalName,accountEnabled,userType')
                $null = Resolve-Phase2Users -Snapshot @{ Data = @{ Users = @($user) }; Errors = @{} } -Upns @($upn)
                Connect-Phase2Teams -Config $config -DeviceCode:$DeviceCode
                $onlineUser = Get-CsOnlineUser -Identity $upn -ErrorAction Stop
                if ($onlineUser.UserPrincipalName -ne $upn) { throw 'Teams pilot identity verification failed.' }
                $assignments = @(Get-CsUserPolicyAssignment -Identity $upn -PolicyType TeamsMeetingPolicy -ErrorAction Stop)
                if ($assignments.Count -gt 1) { throw 'Ambiguous effective Teams meeting policy.' }
                $baselineName = if ($assignments.Count) { $assignments[0].PolicyName } else { 'Global' }
                if (-not $baselineName) { throw 'Effective policy name was not returned.' }
                $policies = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop)
                $baseline = @($policies | Where-Object { ($_.Identity -replace '^Tag:', '') -eq ($baselineName -replace '^Tag:', '') })
                if ($baseline.Count -ne 1) { throw 'Effective Teams baseline could not be resolved.' }
                $parameters = (Get-Command New-CsTeamsMeetingPolicy -ErrorAction Stop).Parameters
                $desired = @{}
                foreach ($property in $baseline[0].PSObject.Properties) {
                    if ($property.Name -notin @('Identity', 'Description', 'AllowCarbonSummary') -and $parameters.ContainsKey($property.Name) -and $null -ne $property.Value) {
                        $desired[$property.Name] = $property.Value
                    }
                }
                $desired.AutoAdmittedUsers = 'InvitedUsers'
                $desired.DesignatedPresenterRoleMode = 'OrganizerOnlyUserOverride'
                $desired.AllowAnonymousUsersToJoinMeeting = $false
                $existing = @($policies | Where-Object { ($_.Identity -replace '^Tag:', '') -eq $config.TeamsPilotPolicyName })
                if ($existing.Count -gt 1) { throw 'Duplicate Teams pilot policy names.' }
                if ($existing.Count) {
                    foreach ($key in $desired.Keys) {
                        if ((ConvertTo-Phase2CanonicalJson $existing[0].$key) -cne (ConvertTo-Phase2CanonicalJson $desired[$key])) {
                            throw "Existing Teams pilot policy differs at $key; it will not be overwritten."
                        }
                    }
                }
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'teams-before' -Value @{
                    TenantId = $config.TenantId; PilotUpn = $upn; DirectPolicy = $onlineUser.TeamsMeetingPolicy
                    EffectiveAssignments = $assignments; Baseline = $baseline[0]; ExistingPilot = $existing; DesiredSettings = $desired
                }
                if ($Apply -and $PSCmdlet.ShouldProcess($upn, "Create or reuse $($config.TeamsPilotPolicyName) and assign it to this pilot only")) {
                    if (-not $existing.Count) {
                        $created = New-CsTeamsMeetingPolicy -Identity $config.TeamsPilotPolicyName @desired -ErrorAction Stop
                        $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'teams-created' -Value @{
                            TenantId = $config.TenantId; BeforeFile = $beforeFile; Policy = $created
                        }
                    }
                    $verified = Get-CsTeamsMeetingPolicy -Identity $config.TeamsPilotPolicyName -ErrorAction Stop
                    foreach ($key in $desired.Keys) {
                        if ((ConvertTo-Phase2CanonicalJson $verified.$key) -cne (ConvertTo-Phase2CanonicalJson $desired[$key])) {
                            throw "Teams policy read-back differs at $key; the pilot assignment was not changed."
                        }
                    }
                    $null = Grant-CsTeamsMeetingPolicy -Identity $upn -PolicyName $config.TeamsPilotPolicyName -ErrorAction Stop
                    $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'teams-granted' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; PilotUpn = $upn; PolicyName = $config.TeamsPilotPolicyName
                    }
                    $afterAssignments = @(Get-CsUserPolicyAssignment -Identity $upn -PolicyType TeamsMeetingPolicy -ErrorAction Stop)
                    $afterFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'teams-after' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; Policy = $verified; Assignments = $afterAssignments
                    }
                    $status = if ($afterAssignments.Count -eq 1 -and ($afterAssignments[0].PolicyName -replace '^Tag:', '') -eq $config.TeamsPilotPolicyName) {
                        'STAGED'
                    } else { 'PENDING-PROPAGATION' }
                    $results.Add(@{ Action = $step; Status = $status; Evidence = $afterFile; Note = 'Only the pilot is assigned. Verify propagation and live meeting behavior; Global and other policies are unchanged.' })
                }
                else { $results.Add(@{ Action = $step; Status = 'PLANNED'; Evidence = $beforeFile }) }
            }
            'Consent' {
                $users = @(foreach ($upn in $config.ReviewerUpns) {
                    Invoke-Phase2Graph ('/users/' + [uri]::EscapeDataString($upn) + '?$select=id,userPrincipalName,accountEnabled,userType')
                })
                $expected = Get-Phase2ConsentBody -Config $config -Snapshot @{ Data = @{ Users = $users }; Errors = @{} }
                $authorization = Invoke-Phase2Graph '/policies/authorizationPolicy'
                $consent = Invoke-Phase2Graph '/policies/adminConsentRequestPolicy'
                if (-not $authorization.defaultUserRolePermissions.ContainsKey('permissionGrantPoliciesAssigned')) {
                    throw 'User consent assignments were not returned; no writes are allowed.'
                }
                $permissions = $authorization.defaultUserRolePermissions | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
                $permissions.permissionGrantPoliciesAssigned = @($permissions.permissionGrantPoliciesAssigned | Where-Object {
                    $_ -notlike 'ManagePermissionGrantsForSelf.*'
                })
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'consent-before' -Value @{
                    TenantId = $config.TenantId; Operator = $operator.userPrincipalName
                    Authorization = $authorization; Consent = $consent; Reviewers = $users
                    DesiredConsent = $expected; DesiredPermissions = $permissions
                }
                if ($Apply -and $PSCmdlet.ShouldProcess($config.TenantDomain, 'Enable reviewer workflow, then disable ordinary-user self-consent')) {
                    $null = Invoke-Phase2Graph -Path '/policies/adminConsentRequestPolicy' -Method PUT -Body $expected
                    $workflow = Invoke-Phase2Graph '/policies/adminConsentRequestPolicy'
                    $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'consent-workflow' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; Consent = $workflow
                    }
                    if (-not (Test-Phase2ConsentShape -Actual $workflow -Expected $expected)) {
                        throw 'Workflow read-back differs from the requested configuration; user consent was not changed.'
                    }
                    $latest = Invoke-Phase2Graph '/policies/authorizationPolicy'
                    if ((ConvertTo-Phase2CanonicalJson $latest.defaultUserRolePermissions) -cne
                        (ConvertTo-Phase2CanonicalJson $authorization.defaultUserRolePermissions)) {
                        throw 'Default user permissions changed during preflight; review before retrying.'
                    }
                    $null = Invoke-Phase2Graph -Path '/policies/authorizationPolicy' -Method PATCH -Body @{ defaultUserRolePermissions = $permissions }
                    $verified = Invoke-Phase2Graph '/policies/authorizationPolicy'
                    $afterFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'consent-after' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; Authorization = $verified; Consent = $workflow
                    }
                    if ((ConvertTo-Phase2CanonicalJson $verified.defaultUserRolePermissions) -cne (ConvertTo-Phase2CanonicalJson $permissions)) {
                        throw 'User consent read-back failed; inspect evidence before retrying.'
                    }
                    $results.Add(@{ Action = $step; Status = 'IMPLEMENTED'; Evidence = $afterFile
                        Note = 'Reviewers receive requests but gain no approval rights. Administrator approval handoff and notifications need a live test.' })
                }
                else { $results.Add(@{ Action = $step; Status = 'PLANNED'; Evidence = $beforeFile }) }
            }
        }
    }
    catch {
        $failureFile = Save-Phase2Evidence -Directory $OutputDirectory -Label "$step-incomplete" -Value @{
            TenantId = $config.TenantId; BeforeFile = $beforeFile; Error = $_.Exception.Message
        }
        $results.Add(@{ Action = $step; Status = 'INCOMPLETE'; Evidence = $failureFile; Note = $_.Exception.Message })
    }
}
$reportFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'implementation' -Value @{
    TenantId = $config.TenantId; Operator = $operator.userPrincipalName; CheckedAt = [datetimeoffset]::UtcNow.ToString('o')
    Results = $results.ToArray(); Apply = [bool]$Apply
}
$results | ForEach-Object { [pscustomobject]$_ } | Format-Table Action,Status,Evidence,Note -Wrap
Write-Host "Evidence: $reportFile"
if (@($results | Where-Object { $_.Status -eq 'INCOMPLETE' }).Count) {
    throw "One or more actions are incomplete. Review $reportFile before retrying; no automatic rollback was attempted."
}