#Requires -Version 7.2
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string] $ConfigPath = (Join-Path $PSScriptRoot 'config.json'),
    [string] $OutputDirectory = (Join-Path $PSScriptRoot 'reports'),
    [ValidateSet('Consent', 'ConditionalAccessPilot', 'TeamsPilot', 'License', 'PimEligibility')]
    [ValidateNotNullOrEmpty()] [string[]] $Action = @('ConditionalAccessPilot', 'TeamsPilot', 'Consent'),
    [switch] $Apply,
    [switch] $DeviceCode,
    [switch] $EmergencyAccessTested,
    [string] $LicenseUserUpn,
    [guid] $LicenseSkuId
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
if ($Apply -and -not $WhatIfPreference -and 'License' -in $Action) {
    $scopes += 'LicenseAssignment.ReadWrite.All'
}
if ($Apply -and -not $WhatIfPreference -and 'PimEligibility' -in $Action) {
    $scopes += @('RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.Directory')
}
$operator = Connect-Phase2Graph -Config $config -WriteScopes $scopes -DeviceCode:$DeviceCode
$results = [System.Collections.Generic.List[object]]::new()

foreach ($step in @($Action | Select-Object -Unique)) {
    $beforeFile = $null
    try {
        switch ($step) {
            'PimEligibility' {
                if (-not $config.PimAssignments.Count) { throw 'Explicit PIM nominations are required.' }
                $snapshot = Get-Phase2Snapshot -Config $config -SkipTeams
                $users = @(Resolve-Phase2Users $snapshot @($config.PimAssignments.Upn | Sort-Object -Unique))
                Assert-Phase2Readiness -Snapshot $snapshot -Users $users -Registration
                $roles = @(Get-Phase2Data $snapshot 'Roles')
                $assignments = @(Get-Phase2Data $snapshot 'RolePolicyAssignments')
                $eligible = @(Get-Phase2Data $snapshot 'EligibleSchedules')
                $direct = @(Get-Phase2Data $snapshot 'RoleAssignments')
                $requests = @(Get-Phase2Collection '/roleManagement/directory/roleEligibilityScheduleRequests')
                $plans = [System.Collections.Generic.List[object]]::new()
                $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
                $now = [datetimeoffset]::UtcNow
                foreach ($nomination in $config.PimAssignments) {
                    if ($nomination.Upn -in $config.EmergencyUpns -or -not $seen.Add("$($nomination.Upn):$($nomination.RoleDefinitionId)")) {
                        throw 'Emergency or duplicate PIM nomination rejected.'
                    }
                    $user = @($users | Where-Object userPrincipalName -eq $nomination.Upn)[0]
                    $role = @($roles | Where-Object { $_.id -eq $nomination.RoleDefinitionId -and $_.isBuiltIn -eq $true })
                    if ($role.Count -ne 1 -or $role[0].id -notin @('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '69091246-20e8-4a56-aa4d-066075b2a7a8')) {
                        throw 'Only the approved Conditional Access Administrator and Teams Administrator roles are supported.'
                    }
                    $policy = @($assignments | Where-Object { $_.roleDefinitionId -eq $role[0].id -and $_.scopeId -eq '/' -and $_.scopeType -eq 'DirectoryRole' })
                    if ($policy.Count -ne 1) { throw 'PIM role policy assignment is missing or ambiguous.' }
                    if ($snapshot.Errors.ContainsKey("PimRules:$($role[0].id)")) { throw $snapshot.Errors["PimRules:$($role[0].id)"] }
                    $rules = @($snapshot.Data.PimRules[$role[0].id])
                    $expiration = @($rules | Where-Object id -eq 'Expiration_EndUser_Assignment')
                    $enablement = @($rules | Where-Object id -eq 'Enablement_EndUser_Assignment')
                    $eligibilityLimit = @($rules | Where-Object id -eq 'Expiration_Admin_Eligibility')
                    if ($expiration.Count -ne 1 -or $enablement.Count -ne 1 -or $eligibilityLimit.Count -ne 1) { throw 'Required PIM rules are missing.' }
                    $activationDuration = [Xml.XmlConvert]::ToTimeSpan($expiration[0].maximumDuration)
                    if ($activationDuration -le [timespan]::Zero) { throw 'Invalid PIM activation duration.' }
                    if ($activationDuration -gt [timespan]::FromHours(1)) { $activationDuration = [timespan]::FromHours(1) }
                    $eligibilityDuration = [timespan]::FromDays(90)
                    if ($eligibilityLimit[0].isExpirationRequired -eq $true) {
                        $maximum = [Xml.XmlConvert]::ToTimeSpan($eligibilityLimit[0].maximumDuration)
                        if ($maximum -le [timespan]::Zero) { throw 'Invalid PIM eligibility duration.' }
                        if ($maximum -lt $eligibilityDuration) { $eligibilityDuration = $maximum }
                    }
                    $desiredRules = @(
                        @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyExpirationRule'; id = $expiration[0].id; target = $expiration[0].target; isExpirationRequired = $true; maximumDuration = [Xml.XmlConvert]::ToString($activationDuration) },
                        @{ '@odata.type' = '#microsoft.graph.unifiedRoleManagementPolicyEnablementRule'; id = $enablement[0].id; target = $enablement[0].target; enabledRules = @(@($enablement[0].enabledRules) + @('MultiFactorAuthentication', 'Justification') | Sort-Object -Unique) }
                    )
                    foreach ($rule in $desiredRules) {
                        if ($rule.target.caller -ne 'EndUser' -or $rule.target.level -ne 'Assignment') { throw 'Unexpected PIM activation rule target.' }
                    }
                    $roleNominations = @($users | Where-Object { $_.userPrincipalName -in @($config.PimAssignments | Where-Object RoleDefinitionId -eq $role[0].id | ForEach-Object { $_.Upn }) })
                    if (@($eligible | Where-Object { $_.roleDefinitionId -eq $role[0].id -and $_.principalId -notin $roleNominations.id }).Count) {
                        throw 'Other users have eligibility for this role; shared activation-policy changes require separate impact review.'
                    }
                    $existing = @($eligible | Where-Object { $_.principalId -eq $user.id -and $_.roleDefinitionId -eq $role[0].id -and $_.directoryScopeId -eq '/' })
                    if ($existing.Count -gt 1) { throw 'Multiple eligibility instances require reconciliation.' }
                    if ($existing.Count -eq 1 -and (-not $existing[0].startDateTime -or -not $existing[0].endDateTime -or
                        [datetimeoffset]$existing[0].startDateTime -gt $now -or [datetimeoffset]$existing[0].endDateTime -le $now -or
                        [datetimeoffset]$existing[0].endDateTime -gt $now.Add($eligibilityDuration))) { throw 'Existing eligibility is not current and time-bounded as intended; it will not be overwritten.' }
                    if (-not $existing.Count) {
                        if (@($direct | Where-Object { $_.principalId -eq $user.id -and $_.roleDefinitionId -eq $role[0].id }).Count) { throw 'A direct assignment already grants this role; no standing roles will be removed.' }
                        if (@($requests | Where-Object { $_.principalId -eq $user.id -and $_.roleDefinitionId -eq $role[0].id -and
                            $_.status -notin @('Canceled', 'Denied', 'Failed', 'Revoked', 'ScheduleRemoved') }).Count) { throw 'An earlier eligibility request needs reconciliation before submitting another.' }
                    }
                    $plans.Add(@{
                        User = $user; Role = $role[0]; PolicyId = $policy[0].policyId; BeforeRules = $rules; DesiredRules = $desiredRules; Existing = $existing
                        Request = @{ action = 'adminAssign'; principalId = $user.id; roleDefinitionId = $role[0].id; directoryScopeId = '/'; justification = 'Phase2 approved least-privilege pilot; activation testing required before standing-access retirement.'
                            scheduleInfo = @{ startDateTime = $now.ToString('o'); expiration = @{ type = 'afterDateTime'; endDateTime = $now.Add($eligibilityDuration).ToString('o') } } }
                    })
                }
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'pim-before' -Value @{ TenantId = $config.TenantId; Plans = $plans.ToArray(); Snapshot = $snapshot }
                if ($Apply -and $PSCmdlet.ShouldProcess(($config.PimAssignments.Upn -join ', '), 'Set role-wide activation to at most one hour with MFA/justification and add at most 90-day eligibility; retain standing access')) {
                    foreach ($plan in $plans) {
                        $rulesPath = "/policies/roleManagementPolicies/$($plan.PolicyId)/rules"
                        $latestRules = @(Get-Phase2Collection $rulesPath)
                        if ((ConvertTo-Phase2CanonicalJson $latestRules) -cne (ConvertTo-Phase2CanonicalJson $plan.BeforeRules)) { throw 'PIM rules changed during preflight; reconcile before retrying.' }
                        $latestEligible = @(Get-Phase2Collection '/roleManagement/directory/roleEligibilityScheduleInstances' | Where-Object roleDefinitionId -eq $plan.Role.id)
                        if ((ConvertTo-Phase2CanonicalJson $latestEligible) -cne (ConvertTo-Phase2CanonicalJson @($eligible | Where-Object roleDefinitionId -eq $plan.Role.id))) { throw 'PIM eligibility changed during preflight.' }
                        foreach ($rule in $plan.DesiredRules) {
                            $beforeRule = @($latestRules | Where-Object id -eq $rule.id)[0]
                            $projection = @{}
                            foreach ($key in $rule.Keys) { $projection[$key] = $beforeRule[$key] }
                            if ((ConvertTo-Phase2CanonicalJson $projection) -cne (ConvertTo-Phase2CanonicalJson $rule)) {
                                $null = Invoke-Phase2Graph -Path "$rulesPath/$($rule.id)" -Method PATCH -Body $rule
                            }
                            $verified = Invoke-Phase2Graph "$rulesPath/$($rule.id)"
                            $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'pim-rule-after' -Value @{ TenantId = $config.TenantId; BeforeFile = $beforeFile; PolicyId = $plan.PolicyId; Rule = $verified }
                            $projection = @{}
                            foreach ($key in $rule.Keys) { $projection[$key] = $verified[$key] }
                            if ((ConvertTo-Phase2CanonicalJson $projection) -cne (ConvertTo-Phase2CanonicalJson $rule)) { throw 'PIM rule read-back failed; no eligibility request submitted for this target.' }
                        }
                        if (-not $plan.Existing.Count) {
                            $latestRequests = @(Get-Phase2Collection '/roleManagement/directory/roleEligibilityScheduleRequests')
                            if (@($latestRequests | Where-Object { $_.principalId -eq $plan.User.id -and $_.roleDefinitionId -eq $plan.Role.id -and $_.status -notin @('Canceled', 'Denied', 'Failed', 'Revoked', 'ScheduleRemoved') }).Count) { throw 'An eligibility request appeared; reconcile before resubmitting.' }
                            $receipt = Invoke-Phase2Graph -Path '/roleManagement/directory/roleEligibilityScheduleRequests' -Method POST -Body $plan.Request
                            $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'pim-requested' -Value @{ TenantId = $config.TenantId; BeforeFile = $beforeFile; Request = $plan.Request; Receipt = $receipt }
                            if (-not $receipt.id -or $receipt.status -in @('Failed', 'Denied', 'Canceled')) { throw 'PIM eligibility request was not accepted; inspect the receipt.' }
                        }
                    }
                    $after = @(Get-Phase2Collection '/roleManagement/directory/roleEligibilityScheduleInstances')
                    $status = 'STAGED'
                    foreach ($plan in $plans) {
                        $matches = @($after | Where-Object { $_.principalId -eq $plan.User.id -and $_.roleDefinitionId -eq $plan.Role.id -and $_.directoryScopeId -eq '/' -and
                            $_.startDateTime -and $_.endDateTime -and [datetimeoffset]$_.startDateTime -le [datetimeoffset]::UtcNow -and
                            [datetimeoffset]$_.endDateTime -gt [datetimeoffset]::UtcNow -and [datetimeoffset]$_.endDateTime -le [datetimeoffset]$plan.Request.scheduleInfo.expiration.endDateTime })
                        if ($matches.Count -ne 1) { $status = 'PENDING-PROPAGATION' }
                    }
                    $afterFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'pim-after' -Value @{ TenantId = $config.TenantId; BeforeFile = $beforeFile; Eligibility = $after; Status = $status }
                    $results.Add(@{ Action = $step; Status = $status; Evidence = $afterFile; Note = 'Eligibility and role-wide activation controls staged. Standing roles retained; successful human activation and least-privilege testing required.' })
                }
                else { $results.Add(@{ Action = $step; Status = 'PLANNED'; Evidence = $beforeFile }) }
            }
            'License' {
                if (-not $LicenseUserUpn -or $LicenseSkuId -eq [guid]::Empty -or $LicenseUserUpn -in $config.EmergencyUpns) {
                    throw 'Specify an approved non-emergency LicenseUserUpn and LicenseSkuId.'
                }
                $userPath = '/users/' + [uri]::EscapeDataString($LicenseUserUpn)
                $select = '?$select=id,userPrincipalName,accountEnabled,userType,usageLocation,assignedLicenses,assignedPlans,licenseAssignmentStates'
                $user = Invoke-Phase2Graph ($userPath + $select)
                $null = Resolve-Phase2Users -Snapshot @{ Data = @{ Users = @($user) }; Errors = @{} } -Upns @($LicenseUserUpn)
                if ($user.usageLocation -notmatch '^[A-Z]{2}$') { throw 'A verified usage location is required; none will be inferred.' }
                $skus = @(Get-Phase2Collection '/subscribedSkus')
                $sku = @($skus | Where-Object { $_.skuId -eq $LicenseSkuId.ToString() -and $_.capabilityStatus -eq 'Enabled' })
                if ($sku.Count -ne 1) { throw 'The nominated license SKU is not uniquely available and enabled.' }
                $planIds = @($sku[0].servicePlans | Where-Object {
                    $_.servicePlanName -in @('AAD_PREMIUM', 'AAD_PREMIUM_P2') -and $_.provisioningStatus -eq 'Success'
                } | ForEach-Object { $_.servicePlanId })
                if (-not $planIds.Count) { throw 'The SKU contains no provisioned Entra P1/P2 service plan.' }
                if (@($user.assignedPlans | Where-Object { $_.servicePlanId -in $planIds -and $_.capabilityStatus -eq 'Enabled' }).Count) {
                    $results.Add(@{ Action = $step; Status = 'IMPLEMENTED'; Note = 'Entra P1/P2 entitlement already enabled; no license changes.' })
                    continue
                }
                if ($LicenseSkuId.ToString() -in @($user.assignedLicenses.skuId)) {
                    throw 'The SKU is already assigned with disabled or pending Entra services; reconcile it without replacing existing settings.'
                }
                if ($null -eq $sku[0].prepaidUnits.enabled -or $null -eq $sku[0].consumedUnits -or
                    ($sku[0].prepaidUnits.enabled - $sku[0].consumedUnits) -lt 1) { throw 'No available seat in the nominated SKU.' }
                $disabledPlans = @($sku[0].servicePlans | Where-Object { $_.servicePlanId -notin $planIds } | ForEach-Object { $_.servicePlanId })
                $body = @{ addLicenses = @(@{ skuId = $LicenseSkuId.ToString(); disabledPlans = $disabledPlans }); removeLicenses = @() }
                $beforeFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'license-before' -Value @{
                    TenantId = $config.TenantId; User = $user; Sku = $sku[0]; Desired = $body
                }
                if ($Apply -and $PSCmdlet.ShouldProcess($LicenseUserUpn, "Assign one existing $($sku[0].skuPartNumber) seat with only Entra P1/P2 enabled")) {
                    $latest = Invoke-Phase2Graph ($userPath + $select)
                    if ((ConvertTo-Phase2CanonicalJson $latest.assignedLicenses) -cne (ConvertTo-Phase2CanonicalJson $user.assignedLicenses)) {
                        throw 'License assignments changed during preflight; no assignment was submitted.'
                    }
                    $receipt = Invoke-Phase2Graph -Path ($userPath + '/assignLicense') -Method POST -Body $body
                    $null = Save-Phase2Evidence -Directory $OutputDirectory -Label 'license-assigned' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; Receipt = $receipt
                    }
                    $after = Invoke-Phase2Graph ($userPath + $select)
                    $afterFile = Save-Phase2Evidence -Directory $OutputDirectory -Label 'license-after' -Value @{
                        TenantId = $config.TenantId; BeforeFile = $beforeFile; User = $after
                    }
                    $assigned = @($after.assignedLicenses | Where-Object skuId -eq $LicenseSkuId.ToString())
                    if ($assigned.Count -ne 1) {
                        throw 'Assigned license read-back differs; reconcile evidence before retrying.'
                    }
                    if ((ConvertTo-Phase2CanonicalJson $assigned[0].disabledPlans) -cne (ConvertTo-Phase2CanonicalJson $disabledPlans)) {
                        $companyPlans = @($sku[0].servicePlans | Where-Object appliesTo -eq 'Company' | ForEach-Object { $_.servicePlanId })
                        $omitted = @($disabledPlans | Where-Object { $_ -notin $assigned[0].disabledPlans })
                        $unexpected = @($assigned[0].disabledPlans | Where-Object { $_ -notin $disabledPlans })
                        $directState = @($after.licenseAssignmentStates | Where-Object { $_.skuId -eq $LicenseSkuId.ToString() -and -not $_.assignedByGroup })
                        if ($unexpected.Count -or @($omitted | Where-Object { $_ -notin $companyPlans }).Count -or
                            $directState.Count -ne 1 -or $directState[0].state -ne 'Active' -or $directState[0].error -ne 'None' -or
                            (ConvertTo-Phase2CanonicalJson $directState[0].disabledPlans) -cne (ConvertTo-Phase2CanonicalJson $disabledPlans)) {
                            throw 'Assigned license read-back differs beyond verified company-plan omissions; reconcile evidence before retrying.'
                        }
                    }
                    foreach ($prior in $user.assignedLicenses) {
                        $preserved = @($after.assignedLicenses | Where-Object skuId -eq $prior.skuId)
                        if ($preserved.Count -ne 1 -or (ConvertTo-Phase2CanonicalJson $preserved[0]) -cne (ConvertTo-Phase2CanonicalJson $prior)) {
                            throw 'An existing license changed; inspect evidence before any further action.'
                        }
                    }
                    $failed = @($after.licenseAssignmentStates | Where-Object { $_.skuId -eq $LicenseSkuId.ToString() -and $_.state -in @('Error', 'ActiveWithError') })
                    if ($failed.Count) { throw 'The license assignment reports a provisioning error; inspect evidence.' }
                    $status = if (@($after.assignedPlans | Where-Object { $_.servicePlanId -in $planIds -and $_.capabilityStatus -eq 'Enabled' }).Count) { 'IMPLEMENTED' } else { 'PENDING-PROPAGATION' }
                    $results.Add(@{ Action = $step; Status = $status; Evidence = $afterFile; Note = 'Existing licenses preserved; no purchase. Entra P1/P2 enabled and other user-scoped plans disabled. Company-scoped plans are not user-level controls.' })
                }
                else { $results.Add(@{ Action = $step; Status = 'PLANNED'; Evidence = $beforeFile }) }
            }
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