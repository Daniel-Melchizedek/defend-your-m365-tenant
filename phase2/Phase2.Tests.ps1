#Requires -Version 7.2
BeforeAll {
    Import-Module (Join-Path $PSScriptRoot 'Phase2.Common.psm1') -Force
    Import-Module MicrosoftTeams -MinimumVersion 6.4.0
    $script:deployPath = Join-Path $PSScriptRoot 'Enforce-Phase2Hardening.ps1'
}
AfterAll { Remove-Variable Phase2TestState -Scope Global -ErrorAction SilentlyContinue }

Describe 'Canonical policy comparison' {
    It 'accepts service-normalized consent without mutating evidence' {
        $expected = @{ isEnabled = $true; notifyReviewers = $true; reviewers = @(@{ query = '/users/reviewer-one'; queryType = 'MicrosoftGraph' }) }
        $actual = @{ isEnabled = $true; notifyReviewers = $true; reviewers = @(@{ query = '/v1.0/users/reviewer-one'; queryType = 'MicrosoftGraph'; queryRoot = $null }); version = 0 }
        Test-Phase2ConsentShape -Actual $actual -Expected $expected | Should -BeTrue
        $actual.reviewers[0].query | Should -Be '/v1.0/users/reviewer-one'
        $actual.notifyReviewers = $false
        Test-Phase2ConsentShape -Actual $actual -Expected $expected | Should -BeFalse
    }

    It 'compares wrapped strings by value rather than their adapted properties' {
        $wrapped = ([guid]'00000000-0000-0000-0000-000000000004').Guid
        (ConvertTo-Phase2CanonicalJson @{ id = $wrapped }) | Should -Be '{"id":"00000000-0000-0000-0000-000000000004"}'
    }

    It 'matches every generated policy after a JSON round-trip' {
        $definitions = @(Get-Phase2CaDefinitions -IncludedUserIds @('pilot-id') -EmergencyUserIds @('emergency-one','emergency-two') -StrengthId '00000000-0000-0000-0000-000000000004')
        foreach ($definition in $definitions) {
            $actual = $definition.Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
            Test-Phase2CaShape $actual $definition.Body | Should -BeTrue
        }
    }
}

Describe 'Emergency assignment date verification' {
    BeforeEach {
        $config = @{ TenantDomain = 'example.onmicrosoft.com'; EmergencyUpns = @('first@example.onmicrosoft.com', 'second@example.onmicrosoft.com') }
        $snapshot = @{ Errors = @{}; Data = @{
            Users = @($config.EmergencyUpns | ForEach-Object { @{ id = $_; userPrincipalName = $_; accountEnabled = $true; userType = 'Member' } })
            Roles = @(@{ id = 'ga-role'; templateId = '62e90394-69f5-4237-9190-012177145e10' })
            ActiveSchedules = @($config.EmergencyUpns | ForEach-Object { @{ principalId = $_; roleDefinitionId = 'ga-role'; directoryScopeId = '/'; assignmentType = 'Assigned'; endDateTime = $null; startDateTime = '2020-01-01T00:00:00Z' } })
        } }
    }

    It 'accepts both permanent assignments with past start dates' {
        @(Assert-Phase2EmergencyAccess $config $snapshot) | Should -HaveCount 2
    }

    It 'reports null or absent start dates as unverified without a conversion error' {
        $snapshot.Data.ActiveSchedules[0].startDateTime = $null
        { Assert-Phase2EmergencyAccess $config $snapshot } | Should -Throw '*Missing start dates require separate verification*'
        $snapshot.Data.ActiveSchedules[0].Remove('startDateTime')
        { Assert-Phase2EmergencyAccess $config $snapshot } | Should -Throw '*Missing start dates require separate verification*'
    }

    It 'rejects a future assignment start' {
        $snapshot.Data.ActiveSchedules[0].startDateTime = [datetimeoffset]::UtcNow.AddDays(1).ToString('o')
        { Assert-Phase2EmergencyAccess $config $snapshot } | Should -Throw '*lacks a verified permanent active*'
    }
}

Describe 'Consolidated read-only assessment' {
    BeforeEach {
        $global:Phase2TestState = @{
            Config = @{ TenantId = 'tenant-id'; PilotUpns = @('pilot@example.com'); TeamsPilotPolicyName = 'Phase2-SecureMeetings'; EmergencyUpns = @() }
            Snapshot = @{ CheckedAt = 'test'; Errors = @{}; Data = @{
                SecurityDefaults = @{ isEnabled = $true }
                Teams = @([pscustomobject]@{ Identity = 'Tag:Phase2-SecureMeetings'; AutoAdmittedUsers = 'InvitedUsers'; DesignatedPresenterRoleMode = 'OrganizerOnlyUserOverride'; AllowAnonymousUsersToJoinMeeting = $false })
            } }
        }
        Mock Import-Module {}
        Mock Read-Phase2Config { $global:Phase2TestState.Config }
        Mock Connect-Phase2Graph { @{ userPrincipalName = 'operator@example.com' } }
        Mock Get-Phase2Snapshot { $global:Phase2TestState.Snapshot }
        Mock Resolve-Phase2Users { @{ id = 'pilot-id' } }
        Mock Assert-Phase2Readiness {}
        Mock Assert-Phase2EmergencyAccess { throw 'Unverified permanence' }
        Mock Get-Phase2CaAssessment { @{ Status = 'NOT-CONFIGURED'; Evidence = 'test' } }
        Mock Get-Phase2ConsentBody { throw 'No fixture consent' }
        Mock Get-Phase2PimAssessment { throw 'Deferred' }
        Mock Get-CsUserPolicyAssignment { [pscustomobject]@{ PolicyName = 'Phase2-SecureMeetings' } }
        Mock Invoke-Phase2Graph { throw 'Unexpected Graph call' }
        Mock Save-Phase2Evidence { $global:Phase2TestState.Report = $Value; 'evidence.json' }
    }

    It 'collects migration and effective pilot evidence without write scopes' {
        & (Join-Path $PSScriptRoot 'Verify-Phase2Hardening.ps1')
        ($global:Phase2TestState.Report.Results | Where-Object Control -eq 'ConditionalAccessMigrationGate').Status | Should -Be 'BLOCKED'
        ($global:Phase2TestState.Report.Results | Where-Object Control -eq 'TeamsPilotAssignment').Status | Should -Be 'STAGED'
        ($global:Phase2TestState.Report.Results | Where-Object Control -eq 'PilotReadiness').Status | Should -Be 'IMPLEMENTED'
        $global:Phase2TestState.Report.Snapshot.Data['TeamsAssignment:pilot@example.com'].Count | Should -Be 1
        Should -Invoke Connect-Phase2Graph -Times 1 -ParameterFilter { $WriteScopes.Count -eq 0 }
        Should -Invoke Invoke-Phase2Graph -Times 0
    }

    It 'does not treat disabled defaults or missing assignment as ready' {
        $global:Phase2TestState.Snapshot.Data.SecurityDefaults.isEnabled = $false
        Mock Get-CsUserPolicyAssignment {}
        & (Join-Path $PSScriptRoot 'Verify-Phase2Hardening.ps1')
        ($global:Phase2TestState.Report.Results | Where-Object Control -eq 'ConditionalAccessMigrationGate').Status | Should -Be 'UNKNOWN'
        ($global:Phase2TestState.Report.Results | Where-Object Control -eq 'TeamsPilotAssignment').Status | Should -Be 'UNKNOWN'
    }
}

Describe 'Consent deployment safety' {
    BeforeEach {
        $global:Phase2TestState = @{}
        $global:Phase2TestState.Config = @{
            TenantId = '8952eb8b-41ff-445d-8d22-ec589f475d13'; TenantDomain = '81c4nz.onmicrosoft.com'
            OperatorUpn = 'operator@81c4nz.onmicrosoft.com'; ReviewerUpns = @('reviewer-one', 'reviewer-two')
        }
        $global:Phase2TestState.InitialPermissions = @{
            allowedToCreateApps = $false; allowedToCreateSecurityGroups = $true
            permissionGrantPoliciesAssigned = @('ManagePermissionGrantsForSelf.example', 'ManagePermissionGrantsForOwnedResource.keep')
        }
        $global:Phase2TestState.CurrentPermissions = $global:Phase2TestState.InitialPermissions
        $global:Phase2TestState.Workflow = @{ isEnabled = $false }
        $global:Phase2TestState.WriteOrder = [System.Collections.Generic.List[string]]::new()
        $global:Phase2TestState.Evidence = [System.Collections.Generic.List[object]]::new()
        Mock Import-Module {}
        Mock Read-Phase2Config { $global:Phase2TestState.Config }
        Mock Connect-Phase2Graph { @{ userPrincipalName = $global:Phase2TestState.Config.OperatorUpn } }
        Mock Get-Phase2ConsentBody { @{ isEnabled = $true; reviewers = @(@{ query = '/users/reviewer-one'; queryType = 'MicrosoftGraph' }) } }
        Mock Save-Phase2Evidence { $global:Phase2TestState.Evidence.Add($Value); 'evidence.json' }
        Mock Invoke-Phase2Graph {
            if ($Path.StartsWith('/users/')) { return @{ id = 'reviewer-id' } }
            if ($Path -eq '/policies/adminConsentRequestPolicy') {
                if ($Method -eq 'PUT') { $global:Phase2TestState.WriteOrder.Add('workflow'); $global:Phase2TestState.Workflow = $Body; return }
                return $global:Phase2TestState.Workflow
            }
            if ($Path -eq '/policies/authorizationPolicy') {
                if ($Method -eq 'PATCH') { $global:Phase2TestState.WriteOrder.Add('authorization'); $global:Phase2TestState.CurrentPermissions = $Body.defaultUserRolePermissions; return }
                return @{ defaultUserRolePermissions = $global:Phase2TestState.CurrentPermissions }
            }
            throw "Unexpected path: $Path"
        }
    }

    It 'defaults to a plan with no writes and no write scopes' {
        & $script:deployPath -Action Consent
        $global:Phase2TestState.WriteOrder.Count | Should -Be 0
        Should -Invoke Connect-Phase2Graph -Times 1 -ParameterFilter { $WriteScopes.Count -eq 0 }
    }

    It 'verifies workflow first and preserves unrelated user permissions' {
        & $script:deployPath -Action Consent -Apply -Confirm:$false
        ($global:Phase2TestState.WriteOrder -join ',') | Should -Be 'workflow,authorization'
        $global:Phase2TestState.CurrentPermissions.allowedToCreateApps | Should -BeFalse
        $global:Phase2TestState.CurrentPermissions.allowedToCreateSecurityGroups | Should -BeTrue
        $global:Phase2TestState.CurrentPermissions.permissionGrantPoliciesAssigned | Should -HaveCount 1
        $global:Phase2TestState.CurrentPermissions.permissionGrantPoliciesAssigned[0] | Should -Be 'ManagePermissionGrantsForOwnedResource.keep'
        $global:Phase2TestState.InitialPermissions.permissionGrantPoliciesAssigned | Should -HaveCount 2
        $global:Phase2TestState.Evidence[-1].Results[0].Status | Should -Be 'IMPLEMENTED'
    }

    It 'does not disable consent if workflow read-back fails' {
        Mock Invoke-Phase2Graph { @{ isEnabled = $false } } -ParameterFilter {
            $Path -eq '/policies/adminConsentRequestPolicy' -and $Method -ne 'PUT'
        }
        { & $script:deployPath -Action Consent -Apply -Confirm:$false } | Should -Throw '*incomplete*'
        Should -Invoke Invoke-Phase2Graph -Times 0 -ParameterFilter { $Method -eq 'PATCH' }
    }

    It 'accepts versioned reviewer paths returned by Graph' {
        Mock Invoke-Phase2Graph {
            @{ isEnabled = $true; reviewers = @(@{ query = '/v1.0/users/reviewer-one'; queryType = 'MicrosoftGraph'; queryRoot = $null }) }
        } -ParameterFilter { $Path -eq '/policies/adminConsentRequestPolicy' -and $Method -ne 'PUT' }
        & $script:deployPath -Action Consent -Apply -Confirm:$false
        Should -Invoke Invoke-Phase2Graph -Times 1 -ParameterFilter { $Method -eq 'PATCH' }
        $global:Phase2TestState.Evidence[-1].Results[0].Status | Should -Be 'IMPLEMENTED'
    }

    It 'rejects a different reviewer even with a versioned path' {
        Mock Invoke-Phase2Graph {
            @{ isEnabled = $true; reviewers = @(@{ query = '/v1.0/users/different-reviewer'; queryType = 'MicrosoftGraph'; queryRoot = $null }) }
        } -ParameterFilter { $Path -eq '/policies/adminConsentRequestPolicy' -and $Method -ne 'PUT' }
        { & $script:deployPath -Action Consent -Apply -Confirm:$false } | Should -Throw '*incomplete*'
        Should -Invoke Invoke-Phase2Graph -Times 0 -ParameterFilter { $Method -eq 'PATCH' }
    }

    It 'honors WhatIf without write scopes or mutations' {
        & $script:deployPath -Action Consent -Apply -WhatIf
        $global:Phase2TestState.WriteOrder.Count | Should -Be 0
        Should -Invoke Connect-Phase2Graph -Times 1 -ParameterFilter { $WriteScopes.Count -eq 0 }
    }
}

Describe 'Pilot deployment boundaries' {
    BeforeEach {
        $global:Phase2TestState = @{
            Config = @{
                TenantId = '8952eb8b-41ff-445d-8d22-ec589f475d13'; TenantDomain = '81c4nz.onmicrosoft.com'
                OperatorUpn = 'pilot@81c4nz.onmicrosoft.com'; PilotUpns = @('pilot@81c4nz.onmicrosoft.com')
                EmergencyUpns = @('emergency-one', 'emergency-two'); TeamsPilotPolicyName = 'Phase2-SecureMeetings'
            }
            Evidence = [System.Collections.Generic.List[object]]::new()
            Baseline = [pscustomobject]@{
                Identity = 'Global'; AutoAdmittedUsers = 'Everyone'; DesignatedPresenterRoleMode = 'EveryoneUserOverride'
                AllowAnonymousUsersToJoinMeeting = $true; AllowCloudRecording = $false; AllowCarbonSummary = $true
            }
            Granted = $false
        }
        Mock Import-Module {}
        Mock Read-Phase2Config { $global:Phase2TestState.Config }
        Mock Connect-Phase2Graph { @{ userPrincipalName = $global:Phase2TestState.Config.OperatorUpn } }
        Mock Connect-Phase2Teams {}
        Mock Save-Phase2Evidence { $global:Phase2TestState.Evidence.Add($Value); 'evidence.json' }
        Mock Invoke-Phase2Graph {
            if ($Path -eq '/policies/identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = $true } }
            if ($Path.StartsWith('/users/')) {
                return @{ id = 'pilot-id'; userPrincipalName = 'pilot@81c4nz.onmicrosoft.com'; accountEnabled = $true; userType = 'Member' }
            }
            throw "Unexpected Graph request: $Path"
        }
        Mock Get-CsOnlineUser { [pscustomobject]@{ UserPrincipalName = 'pilot@81c4nz.onmicrosoft.com'; TeamsMeetingPolicy = $null } }
        Mock Get-CsUserPolicyAssignment {
            if ($global:Phase2TestState.Granted) { [pscustomobject]@{ PolicyName = 'Phase2-SecureMeetings' } }
        }
        Mock Get-CsTeamsMeetingPolicy {
            if ($Identity) { return $global:Phase2TestState.Created }
            $global:Phase2TestState.Baseline
        }
        Mock New-CsTeamsMeetingPolicy {
            $global:Phase2TestState.Created = [pscustomobject]@{
                Identity = "Tag:$Identity"; AutoAdmittedUsers = $AutoAdmittedUsers
                DesignatedPresenterRoleMode = $DesignatedPresenterRoleMode
                AllowAnonymousUsersToJoinMeeting = $AllowAnonymousUsersToJoinMeeting; AllowCloudRecording = $AllowCloudRecording
            }
            $global:Phase2TestState.Created
        }
        Mock Grant-CsTeamsMeetingPolicy { $global:Phase2TestState.Granted = $true }
    }

    It 'leaves Security Defaults enabled and blocks CA writes' {
        & $script:deployPath -Action ConditionalAccessPilot -Apply -EmergencyAccessTested -Confirm:$false
        $global:Phase2TestState.Evidence[-1].Results[0].Status | Should -Be 'BLOCKED'
        Should -Invoke Invoke-Phase2Graph -Times 0 -ParameterFilter { $Method -in @('POST', 'PATCH', 'PUT') }
    }

    It 'does not create or assign Teams policies when planning' {
        & $script:deployPath -Action TeamsPilot
        Should -Invoke New-CsTeamsMeetingPolicy -Times 0
        Should -Invoke Grant-CsTeamsMeetingPolicy -Times 0
    }

    It 'preserves recording settings and assigns only the configured pilot' {
        & $script:deployPath -Action TeamsPilot -Apply -Confirm:$false
        Should -Invoke New-CsTeamsMeetingPolicy -Times 1 -ParameterFilter {
            $Identity -eq 'Phase2-SecureMeetings' -and $AllowCloudRecording -eq $false -and
            $AutoAdmittedUsers -eq 'InvitedUsers' -and $DesignatedPresenterRoleMode -eq 'OrganizerOnlyUserOverride' -and
            $AllowAnonymousUsersToJoinMeeting -eq $false
        }
        Should -Invoke Grant-CsTeamsMeetingPolicy -Times 1 -ParameterFilter {
            $Identity -eq 'pilot@81c4nz.onmicrosoft.com' -and $PolicyName -eq 'Phase2-SecureMeetings'
        }
        $global:Phase2TestState.Evidence[-1].Results[0].Status | Should -Be 'STAGED'
    }

    It 'never assigns a Teams policy that fails read-back verification' {
        Mock Get-CsTeamsMeetingPolicy { $global:Phase2TestState.Baseline } -ParameterFilter { [bool]$Identity }
        { & $script:deployPath -Action TeamsPilot -Apply -Confirm:$false } | Should -Throw '*incomplete*'
        Should -Invoke Grant-CsTeamsMeetingPolicy -Times 0
    }

    It 'omits the service-blocked AllowCarbonSummary parameter' {
        & $script:deployPath -Action TeamsPilot -Apply -Confirm:$false
        $before = @($global:Phase2TestState.Evidence | Where-Object { $_.ContainsKey('DesiredSettings') })[0]
        $before.DesiredSettings.ContainsKey('AllowCarbonSummary') | Should -BeFalse
        $before.DesiredSettings.AllowCloudRecording | Should -BeFalse
        Should -Invoke New-CsTeamsMeetingPolicy -Times 1 -ParameterFilter { -not $PesterBoundParameters.ContainsKey('AllowCarbonSummary') }
    }

    Context 'CA creation with prerequisites satisfied' {
        BeforeEach {
            $global:Phase2TestState.Policies = [System.Collections.Generic.List[object]]::new()
            Mock Assert-Phase2EmergencyAccess { @{ id = 'emergency-one-id' }; @{ id = 'emergency-two-id' } }
            Mock Assert-Phase2Readiness {}
            Mock Resolve-Phase2Users { @{ id = 'pilot-id' } }
            Mock Get-Phase2Collection {
                if ($Path -eq '/identity/conditionalAccess/authenticationStrength/policies') {
                    return @{ id = '00000000-0000-0000-0000-000000000004'; policyType = 'builtIn' }
                }
                if ($Path -eq '/identity/conditionalAccess/policies') { return $global:Phase2TestState.Policies.ToArray() }
            }
            Mock Invoke-Phase2Graph {
                if ($Path -eq '/policies/identitySecurityDefaultsEnforcementPolicy') { return @{ isEnabled = $false } }
                if ($Method -eq 'POST' -and $Path -eq '/identity/conditionalAccess/policies') {
                    $created = $Body | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
                    $created.id = [guid]::NewGuid().ToString()
                    $global:Phase2TestState.Policies.Add($created)
                    return $created
                }
                if ($Path.StartsWith('/identity/conditionalAccess/policies/')) {
                    return $global:Phase2TestState.Policies | Where-Object { $_.id -eq $Path.Split('/')[-1] }
                }
                throw "Unexpected Graph request: $Path"
            }
        }

        It 'creates exactly four report-only policies and does not duplicate them on rerun' {
            try { & $script:deployPath -Action ConditionalAccessPilot -Apply -EmergencyAccessTested -Confirm:$false }
            catch { throw ($global:Phase2TestState.Evidence[-1].Results | ConvertTo-Json -Depth 8) }
            $global:Phase2TestState.Policies | Should -HaveCount 4
            foreach ($policy in $global:Phase2TestState.Policies) {
                $policy.state | Should -Be 'enabledForReportingButNotEnforced'
                $policy.conditions.users.includeUsers | Should -HaveCount 1
                $policy.conditions.users.includeUsers[0] | Should -Be 'pilot-id'
                $policy.conditions.users.excludeUsers | Should -HaveCount 2
            }
            & $script:deployPath -Action ConditionalAccessPilot -Apply -EmergencyAccessTested -Confirm:$false
            Should -Invoke Invoke-Phase2Graph -Times 4 -ParameterFilter { $Method -eq 'POST' }
            Should -Invoke Invoke-Phase2Graph -Times 0 -ParameterFilter { $Method -in @('PATCH', 'PUT') }
        }

        It 'does not downgrade an already enforced policy or create other policies after a conflict' {
            $definition = @(Get-Phase2CaDefinitions -IncludedUserIds @('pilot-id') -EmergencyUserIds @('emergency-one-id','emergency-two-id') -StrengthId '00000000-0000-0000-0000-000000000004')[0]
            $definition.Body.state = 'enabled'
            $global:Phase2TestState.Policies.Add($definition.Body)
            { & $script:deployPath -Action ConditionalAccessPilot -Apply -EmergencyAccessTested -Confirm:$false } | Should -Throw '*incomplete*'
            Should -Invoke Invoke-Phase2Graph -Times 0 -ParameterFilter { $Method -in @('POST', 'PATCH', 'PUT') }
        }
    }
}