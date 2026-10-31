#Requires -Version 7.2

$ErrorActionPreference = 'Stop'

function Get-Phase2CaDefinitions {
    param(
        [Parameter(Mandatory)] [string[]] $IncludedUserIds,
        [Parameter(Mandatory)] [string[]] $EmergencyUserIds,
        [Parameter(Mandatory)] [guid] $StrengthId,
        [ValidateSet('enabledForReportingButNotEnforced', 'enabled')] [string] $State = 'enabledForReportingButNotEnforced'
    )

    if ($EmergencyUserIds.Count -lt 2 -or @($EmergencyUserIds | Sort-Object -Unique).Count -ne $EmergencyUserIds.Count) {
        throw 'At least two distinct emergency users are required.'
    }
    if (@($IncludedUserIds | Where-Object { $_ -in $EmergencyUserIds }).Count) {
        throw 'Emergency users cannot be pilot targets.'
    }
    foreach ($key in @('PhishingResistantMfa', 'BlockLegacy', 'SignInRisk', 'UserRisk')) {
        $conditions = @{
            users = @{ includeUsers = @($IncludedUserIds); excludeUsers = @($EmergencyUserIds) }
            applications = @{ includeApplications = @('All') }
            clientAppTypes = @('all')
        }
        $grant = @{ operator = 'OR'; builtInControls = @('mfa') }
        $session = $null
        switch ($key) {
            'PhishingResistantMfa' { $grant = @{ operator = 'AND'; authenticationStrength = @{ id = $StrengthId.Guid } } }
            'BlockLegacy' {
                $conditions.clientAppTypes = @('exchangeActiveSync', 'other')
                $grant = @{ operator = 'OR'; builtInControls = @('block') }
            }
            'SignInRisk' { $conditions.signInRiskLevels = @('medium', 'high') }
            'UserRisk' {
                $conditions.userRiskLevels = @('high')
                $grant = @{ operator = 'AND'; builtInControls = @('mfa', 'passwordChange') }
            }
        }
        if ($key -in @('SignInRisk', 'UserRisk')) {
            $session = @{ signInFrequency = @{ isEnabled = $true; frequencyInterval = 'everyTime'; authenticationType = 'primaryAndSecondaryAuthentication' } }
        }
        [pscustomobject]@{
            Key = $key
            Body = @{
                displayName = "Phase2-$key"
                state = $State
                conditions = $conditions
                grantControls = $grant
                sessionControls = $session
            }
        }
    }
}

function ConvertTo-Phase2CanonicalJson {
    param([AllowNull()] $Value)

    function Convert-Node {
        param([AllowNull()] $Node)
        if ($null -eq $Node) { return $null }
        if ($Node -is [string] -or $Node -is [ValueType]) { return $Node }
        if ($Node -is [System.Collections.IDictionary] -or $Node -is [pscustomobject]) {
            $dictionary = if ($Node -is [System.Collections.IDictionary]) { $Node } else {
                $converted = @{}
                foreach ($property in $Node.PSObject.Properties) { $converted[$property.Name] = $property.Value }
                $converted
            }
            $result = [ordered]@{}
            foreach ($key in @($dictionary.Keys | Sort-Object)) {
                $child = Convert-Node $dictionary[$key]
                if ($null -ne $child) { $result[$key] = $child }
            }
            if ($result.Count) { return $result }
            return $null
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            $items = @(foreach ($item in $Node) { Convert-Node $item })
            if ($items.Count) { return ,@($items | Sort-Object { ConvertTo-Json -InputObject $_ -Depth 40 -Compress }) }
            return $null
        }
        return $Node
    }

    ConvertTo-Json -InputObject (Convert-Node $Value) -Depth 50 -Compress
}

function Test-Phase2CaShape {
    param([Parameter(Mandatory)] $Actual, [Parameter(Mandatory)] $Expected)

    $grant = @{}
    foreach ($property in @('operator', 'builtInControls', 'customAuthenticationFactors', 'termsOfUse')) {
        $grant[$property] = $Actual.grantControls[$property]
    }
    if ($Actual.grantControls.authenticationStrength) {
        $grant.authenticationStrength = @{ id = $Actual.grantControls.authenticationStrength.id }
    }
    $projection = @{
        conditions = $Actual.conditions
        grantControls = $grant
        sessionControls = $Actual.sessionControls
    }
    $desired = @{
        conditions = $Expected.conditions
        grantControls = $Expected.grantControls
        sessionControls = $Expected.sessionControls
    }
    (ConvertTo-Phase2CanonicalJson $projection) -ceq (ConvertTo-Phase2CanonicalJson $desired)
}

function Read-Phase2Config {
    param([Parameter(Mandatory)] [string] $Path)

    $config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    if ([guid]$config.TenantId -eq [guid]::Empty -or $config.TenantDomain -notmatch '^[a-z0-9-]+\.onmicrosoft\.com$') {
        throw 'A tenant GUID and initial onmicrosoft.com domain are required.'
    }
    if ($config.OperatorUpn -notlike "*@$($config.TenantDomain)") { throw 'Operator must belong to the configured initial domain.' }
    foreach ($field in @('EmergencyUpns', 'PilotUpns', 'ReviewerUpns', 'PimAssignments')) {
        if (-not $config.ContainsKey($field) -or $config[$field] -isnot [array]) { throw "$field must be a JSON array." }
    }
    foreach ($field in @('EmergencyUpns', 'PilotUpns', 'ReviewerUpns')) {
        if (@($config[$field] | Sort-Object -Unique).Count -ne $config[$field].Count) { throw "Duplicate entries in $field." }
    }
    if ($config.OperatorUpn -in $config.EmergencyUpns) { throw 'Do not use an emergency account as the routine operator.' }
    if (@($config.PilotUpns + $config.ReviewerUpns | Where-Object { $_ -in $config.EmergencyUpns }).Count) {
        throw 'Emergency accounts cannot be pilots or routine consent reviewers.'
    }
    foreach ($assignment in $config.PimAssignments) {
        if (-not $assignment.Upn -or [guid]$assignment.RoleDefinitionId -eq [guid]::Empty -or $assignment.Upn -in $config.EmergencyUpns) {
            throw 'Each PIM assignment needs a non-emergency UPN and a role definition GUID.'
        }
    }
    $config
}

function Invoke-Phase2Graph {
    param(
        [Parameter(Mandatory)] [string] $Path,
        [ValidateSet('GET', 'POST', 'PATCH', 'PUT')] [string] $Method = 'GET',
        [hashtable] $Body
    )

    $uri = if ($Path.StartsWith('/')) { "https://graph.microsoft.com/v1.0$Path" } else { $Path }
    if (-not $uri.StartsWith('https://graph.microsoft.com/v1.0/', [StringComparison]::Ordinal)) {
        throw 'Only Microsoft Graph v1.0 in the worldwide cloud is permitted.'
    }
    $parameters = @{ Method = $Method; Uri = $uri; OutputType = 'Hashtable'; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $parameters.Body = ConvertTo-Json -InputObject $Body -Depth 50 -Compress
        $parameters.ContentType = 'application/json'
    }
    Invoke-MgGraphRequest @parameters
}

function Get-Phase2Collection {
    param([Parameter(Mandatory)] [string] $Path)

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    do {
        if (-not $seen.Add($Path) -or $seen.Count -gt 1000) { throw 'Invalid or excessive Graph pagination; inventory is incomplete.' }
        $page = Invoke-Phase2Graph -Path $Path
        if (-not $page.ContainsKey('value')) { throw "Expected a Graph collection: $Path" }
        foreach ($item in $page.value) { $item }
        $Path = $page['@odata.nextLink']
    } while ($Path)
}

function Connect-Phase2Graph {
    param([Parameter(Mandatory)] $Config, [string[]] $WriteScopes = @(), [switch] $DeviceCode)

    Import-Module Microsoft.Graph.Authentication -MinimumVersion 2.19.0 -ErrorAction Stop
    $scopes = @(
        'User.Read.All', 'Organization.Read.All', 'Policy.Read.All',
        'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'RoleManagementPolicy.Read.Directory',
        'RoleEligibilitySchedule.Read.Directory', 'RoleAssignmentSchedule.Read.Directory'
    ) + $WriteScopes | Sort-Object -Unique
    $context = Get-MgContext
    if ($context -and ($context.TenantId -ne $Config.TenantId -or $context.Account -ne $Config.OperatorUpn -or
            $context.AuthType -ne 'Delegated' -or $context.Environment -ne 'Global')) {
        throw 'Existing Graph context is not the expected delegated operator/tenant. Disconnect-MgGraph, then rerun.'
    }
    if (-not $context -or @($scopes | Where-Object { $_ -notin $context.Scopes }).Count) {
        Write-Host "Starting Microsoft Graph sign-in for $($Config.OperatorUpn)."
        Connect-MgGraph -TenantId $Config.TenantId -Scopes $scopes -ContextScope Process -NoWelcome -UseDeviceCode:$DeviceCode -ErrorAction Stop | Out-Host
    }
    $context = Get-MgContext
    if ($context.TenantId -ne $Config.TenantId -or $context.Account -ne $Config.OperatorUpn -or
        $context.AuthType -ne 'Delegated' -or $context.Environment -ne 'Global' -or
        @($scopes | Where-Object { $_ -notin $context.Scopes }).Count) { throw 'Graph connection verification failed.' }
    $operator = Invoke-Phase2Graph '/me?$select=id,userPrincipalName'
    $organizations = @(Get-Phase2Collection '/organization?$select=id,verifiedDomains')
    if ($operator.userPrincipalName -ne $Config.OperatorUpn -or $organizations.Count -ne 1 -or
        $organizations[0].id -ne $Config.TenantId -or
        -not @($organizations[0].verifiedDomains | Where-Object { $_.name -eq $Config.TenantDomain -and $_.isInitial -eq $true }).Count) {
        throw 'Directory identity/domain verification failed.'
    }
    $operator
}

function Connect-Phase2Teams {
    param([Parameter(Mandatory)] $Config, [switch] $DeviceCode)

    Import-Module MicrosoftTeams -MinimumVersion 6.4.0 -ErrorAction Stop
    $connection = Connect-MicrosoftTeams -TenantId $Config.TenantId -AccountId $Config.OperatorUpn -UseDeviceAuthentication:$DeviceCode -ErrorAction Stop
    if ($connection.TenantId -ne $Config.TenantId -or [string]$connection.Account -ne $Config.OperatorUpn) {
        throw 'Teams connection returned an unexpected tenant or account.'
    }
}

function Get-Phase2Snapshot {
    param([Parameter(Mandatory)] $Config, [switch] $SkipTeams, [switch] $DeviceCode)

    $snapshot = @{ TenantId = $Config.TenantId; CheckedAt = [datetimeoffset]::UtcNow.ToString('o'); Data = @{}; Errors = @{} }
    $collections = @{
        Users = '/users?$select=id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,assignedPlans'
        Policies = '/identity/conditionalAccess/policies'
        Strengths = '/identity/conditionalAccess/authenticationStrength/policies'
        Registration = '/reports/authenticationMethods/userRegistrationDetails'
        Roles = '/roleManagement/directory/roleDefinitions'
        RoleAssignments = '/roleManagement/directory/roleAssignments'
        ActiveSchedules = '/roleManagement/directory/roleAssignmentScheduleInstances'
        EligibleSchedules = '/roleManagement/directory/roleEligibilityScheduleInstances'
        Skus = '/subscribedSkus'
        RolePolicyAssignments = "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'"
        SignIns = "/auditLogs/signIns?`$filter=createdDateTime ge $([datetimeoffset]::UtcNow.AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ'))&`$select=id,createdDateTime,userPrincipalName,clientAppUsed,status,conditionalAccessStatus"
    }
    foreach ($entry in $collections.GetEnumerator()) {
        try { $snapshot.Data[$entry.Key] = @(Get-Phase2Collection $entry.Value) }
        catch { $snapshot.Errors[$entry.Key] = $_.Exception.Message }
    }
    foreach ($entry in @{
        Authorization = '/policies/authorizationPolicy'
        Consent = '/policies/adminConsentRequestPolicy'
        SecurityDefaults = '/policies/identitySecurityDefaultsEnforcementPolicy'
    }.GetEnumerator()) {
        try { $snapshot.Data[$entry.Key] = Invoke-Phase2Graph $entry.Value }
        catch { $snapshot.Errors[$entry.Key] = $_.Exception.Message }
    }
    $snapshot.Data.PimRules = @{}
    foreach ($roleId in @($Config.PimAssignments.RoleDefinitionId | Sort-Object -Unique)) {
        try {
            $assignment = @($snapshot.Data.RolePolicyAssignments | Where-Object { $_.roleDefinitionId -eq $roleId })
            if ($assignment.Count -ne 1) { throw 'Role policy assignment is missing or ambiguous.' }
            $snapshot.Data.PimRules[$roleId] = @(Get-Phase2Collection "/policies/roleManagementPolicies/$($assignment[0].policyId)/rules")
        }
        catch { $snapshot.Errors["PimRules:$roleId"] = $_.Exception.Message }
    }
    if ($SkipTeams) { $snapshot.Errors.Teams = 'Teams read explicitly skipped.' }
    else {
        try {
            Connect-Phase2Teams -Config $Config -DeviceCode:$DeviceCode
            $snapshot.Data.Teams = @(Get-CsTeamsMeetingPolicy -ErrorAction Stop | Select-Object Identity,AutoAdmittedUsers,DesignatedPresenterRoleMode,AllowAnonymousUsersToJoinMeeting)
        }
        catch { $snapshot.Errors.Teams = $_.Exception.Message }
    }
    $snapshot
}

function Get-Phase2Data {
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [string] $Key)
    if ($Snapshot.Errors.ContainsKey($Key)) { throw "$Key unavailable: $($Snapshot.Errors[$Key])" }
    if (-not $Snapshot.Data.ContainsKey($Key)) { throw "$Key was not collected." }
    return $Snapshot.Data[$Key]
}

function Resolve-Phase2Users {
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Upns)
    $users = Get-Phase2Data $Snapshot 'Users'
    foreach ($upn in $Upns) {
        $matches = @($users | Where-Object { $_.userPrincipalName -eq $upn })
        if ($matches.Count -ne 1 -or $matches[0].accountEnabled -ne $true -or $matches[0].userType -ne 'Member') {
            throw "Expected one enabled member account: $upn"
        }
        $matches[0]
    }
}

function Assert-Phase2EmergencyAccess {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Snapshot)
    if ($Config.EmergencyUpns.Count -lt 2) { throw 'Nominate at least two tested emergency accounts.' }
    $users = @(Resolve-Phase2Users $Snapshot $Config.EmergencyUpns)
    $roles = @(Get-Phase2Data $Snapshot 'Roles')
    $globalAdmin = @($roles | Where-Object { $_.templateId -eq '62e90394-69f5-4237-9190-012177145e10' })
    if ($globalAdmin.Count -ne 1) { throw 'Global Administrator role definition could not be resolved.' }
    $active = Get-Phase2Data $Snapshot 'ActiveSchedules'
    foreach ($user in $users) {
        if ($user.onPremisesSyncEnabled -eq $true -or $user.userPrincipalName -notlike "*@$($Config.TenantDomain)") {
            throw "Emergency account must be cloud-only in the initial domain: $($user.userPrincipalName)"
        }
        $permanent = @($active | Where-Object {
            $_.principalId -eq $user.id -and $_.roleDefinitionId -eq $globalAdmin[0].id -and
            $_.directoryScopeId -eq '/' -and $_.assignmentType -eq 'Assigned' -and -not $_.endDateTime -and
            $null -ne $_.startDateTime -and
            ([datetimeoffset]$_.startDateTime -le [datetimeoffset]::UtcNow)
        })
        if (-not $permanent.Count) { throw "Emergency account lacks a verified permanent active Global Administrator assignment: $($user.userPrincipalName). Missing start dates require separate verification; no role change is implied." }
    }
    $users
}

function Assert-Phase2Readiness {
    param([Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [array] $Users, [switch] $Registration)
    if (-not $Users.Count) { throw 'Readiness cannot be established for an empty population.' }
    $skus = Get-Phase2Data $Snapshot 'Skus'
    $p2PlanIds = @($skus.servicePlans | Where-Object { $_.servicePlanName -eq 'AAD_PREMIUM_P2' } | ForEach-Object { $_.servicePlanId })
    if (-not $p2PlanIds.Count) { throw 'No Entra ID P2 plan was found. Verify licensing; no licenses are purchased or assigned by these scripts.' }
    $registrationRows = if ($Registration) { Get-Phase2Data $Snapshot 'Registration' } else { @() }
    foreach ($user in $Users) {
        if (-not @($user.assignedPlans | Where-Object { $_.servicePlanId -in $p2PlanIds -and $_.capabilityStatus -eq 'Enabled' }).Count) {
            throw "P2 entitlement is not enabled for $($user.userPrincipalName)."
        }
        if ($Registration) {
            $row = @($registrationRows | Where-Object { $_.id -eq $user.id })
            if ($row.Count -ne 1 -or $row[0].isMfaCapable -ne $true -or $row[0].isSsprCapable -ne $true) {
                throw "MFA/SSPR readiness is incomplete for $($user.userPrincipalName). Reports can lag up to 36 hours."
            }
        }
    }
}

function Save-Phase2Evidence {
    param([Parameter(Mandatory)] [string] $Directory, [Parameter(Mandatory)] [string] $Label, [Parameter(Mandatory)] $Value)
    $null = [IO.Directory]::CreateDirectory([IO.Path]::GetFullPath($Directory))
    $name = '{0}-{1}-{2}.json' -f [datetimeoffset]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'), $Label, [guid]::NewGuid().ToString('N')
    $path = Join-Path $Directory $name
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $Value -Depth 70))
        $stream.Write($bytes, 0, $bytes.Length)
    }
    finally { $stream.Dispose() }
    $path
}

function Get-Phase2CaAssessment {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Snapshot, [Parameter(Mandatory)] [string] $Key)
    $policies = @(Get-Phase2Data $Snapshot 'Policies')
    $strength = @(Get-Phase2Data $Snapshot 'Strengths' | Where-Object {
        $_.id -eq '00000000-0000-0000-0000-000000000004' -and $_.policyType -eq 'builtIn'
    })
    if ($strength.Count -ne 1) { throw 'Built-in phishing-resistant authentication strength was not verified.' }
    $emergency = @(Resolve-Phase2Users $Snapshot $Config.EmergencyUpns)
    $expected = @(Get-Phase2CaDefinitions -IncludedUserIds @('All') -EmergencyUserIds $emergency.id -StrengthId $strength[0].id |
        Where-Object { $_.Key -eq $Key })
    if ($expected.Count -ne 1) { throw 'Unknown Conditional Access definition.' }
    $matching = @($policies | Where-Object { Test-Phase2CaShape -Actual $_ -Expected $expected[0].Body })
    if (@($matching | Where-Object { $_.state -eq 'enabled' }).Count) {
        return @{ Status = 'IMPLEMENTED'; Evidence = 'Enabled, All users/resources, exact intended controls, only nominated emergency exclusions.' }
    }
    if (@($matching | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' }).Count) {
        return @{ Status = 'STAGED'; Evidence = 'Tenant-wide policy is report-only, not enforced.' }
    }
    if ($Config.PilotUpns.Count) {
        $pilots = @(Resolve-Phase2Users $Snapshot $Config.PilotUpns)
        $expected[0].Body.conditions.users.includeUsers = @($pilots.id)
        if (@($policies | Where-Object {
            $_.state -in @('enabled', 'enabledForReportingButNotEnforced') -and (Test-Phase2CaShape -Actual $_ -Expected $expected[0].Body)
        }).Count) { return @{ Status = 'STAGED'; Evidence = 'Only the configured pilot population is covered; tenant-wide rollout is incomplete.' } }
    }
    @{ Status = 'NOT-CONFIGURED'; Evidence = 'No matching enabled or staged policy. Extra filters, exclusions, or alternate grants do not pass this strict check.' }
}

function Get-Phase2ConsentBody {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Snapshot)
    if ($Config.ReviewerUpns.Count -ne 2) { throw 'Nominate exactly two routine admin consent reviewers.' }
    $reviewers = @(Resolve-Phase2Users $Snapshot $Config.ReviewerUpns)
    @{
        isEnabled = $true
        notifyReviewers = $true
        remindersEnabled = $true
        requestDurationInDays = 30
        reviewers = @($reviewers | ForEach-Object { @{ query = "/users/$($_.id)"; queryType = 'MicrosoftGraph' } })
    }
}

function Test-Phase2ConsentShape {
    param([Parameter(Mandatory)] $Actual, [Parameter(Mandatory)] $Expected)
    $projection = @{}
    foreach ($key in $Expected.Keys) { $projection[$key] = $Actual[$key] }
    $projection.reviewers = @(foreach ($reviewer in $Actual.reviewers) {
        $normalized = $reviewer | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $normalized.query = $normalized.query -creplace '^/v1\.0(?=/users/)', ''
        $normalized
    })
    (ConvertTo-Phase2CanonicalJson $projection) -ceq (ConvertTo-Phase2CanonicalJson $Expected)
}

function Test-Phase2TeamsPolicy {
    param([Parameter(Mandatory)] $Policy)
    $Policy.AutoAdmittedUsers -eq 'InvitedUsers' -and
    $Policy.DesignatedPresenterRoleMode -eq 'OrganizerOnlyUserOverride' -and
    $Policy.AllowAnonymousUsersToJoinMeeting -eq $false
}

function Get-Phase2PimAssessment {
    param([Parameter(Mandatory)] $Config, [Parameter(Mandatory)] $Snapshot)
    if (-not $Config.PimAssignments.Count) { throw 'PIM administrators and least-privilege role design are not yet nominated.' }
    $active = @(Get-Phase2Data $Snapshot 'ActiveSchedules')
    $eligible = @(Get-Phase2Data $Snapshot 'EligibleSchedules')
    $roles = @(Get-Phase2Data $Snapshot 'RoleAssignments')
    $now = [datetimeoffset]::UtcNow
    foreach ($desired in $Config.PimAssignments) {
        $user = @(Resolve-Phase2Users $Snapshot @($desired.Upn))[0]
        $matches = @($eligible | Where-Object {
            $_.principalId -eq $user.id -and $_.roleDefinitionId -eq $desired.RoleDefinitionId -and $_.directoryScopeId -eq '/' -and
            [datetimeoffset]$_.startDateTime -le $now -and (-not $_.endDateTime -or [datetimeoffset]$_.endDateTime -gt $now)
        })
        if (-not $matches.Count) { return @{ Status = 'NOT-CONFIGURED'; Evidence = "Missing current eligibility: $($desired.Upn), role $($desired.RoleDefinitionId)." } }
        $errorKey = "PimRules:$($desired.RoleDefinitionId)"
        if ($Snapshot.Errors.ContainsKey($errorKey)) { throw $Snapshot.Errors[$errorKey] }
        $rules = $Snapshot.Data.PimRules[$desired.RoleDefinitionId]
        $expiration = @($rules | Where-Object { $_.id -eq 'Expiration_EndUser_Assignment' })
        $enablement = @($rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' })
        if ($expiration.Count -ne 1 -or $enablement.Count -ne 1) { throw 'PIM activation rules were not returned.' }
        if ($expiration[0].isExpirationRequired -ne $true -or [Xml.XmlConvert]::ToTimeSpan($expiration[0].maximumDuration).TotalHours -gt 1 -or
            'MultiFactorAuthentication' -notin $enablement[0].enabledRules -or 'Justification' -notin $enablement[0].enabledRules) {
            return @{ Status = 'NOT-CONFIGURED'; Evidence = 'PIM activation must expire within one hour and require MFA and justification.' }
        }
        $userActive = @($active | Where-Object { $_.principalId -eq $user.id -and
            [datetimeoffset]$_.startDateTime -le $now -and (-not $_.endDateTime -or [datetimeoffset]$_.endDateTime -gt $now) })
        if (@($userActive | Where-Object { $_.assignmentType -ne 'Activated' }).Count) {
            return @{ Status = 'STAGED'; Evidence = "Eligibility exists but assigned (non-JIT) access remains for $($desired.Upn)." }
        }
        $activationOrigins = @($userActive.roleAssignmentOriginId)
        if (@($roles | Where-Object { $_.principalId -eq $user.id -and $_.id -notin $activationOrigins }).Count) {
            return @{ Status = 'STAGED'; Evidence = "Direct role access not explained by current PIM activations remains for $($desired.Upn)." }
        }
        $memberships = @(Get-Phase2Collection "/users/$($user.id)/transitiveMemberOf?`$select=id")
        if (@($roles | Where-Object { $_.principalId -in @($memberships.id) }).Count) {
            return @{ Status = 'STAGED'; Evidence = "Group-inherited role access remains for $($desired.Upn); review separately. These scripts do not change groups." }
        }
    }
    @{ Status = 'IMPLEMENTED'; Evidence = 'Configured admins have current eligibility, <=1-hour MFA/justification activation, and no detected standing direct/group roles. Live activation and least-privilege suitability still require human testing.' }
}