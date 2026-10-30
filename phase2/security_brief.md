# Microsoft 365 Tenant Security Brief

## Scope and Current Status

Target: WWLCPx73950877.onmicrosoft.com (`7a9b5e57-db07-4525-896c-0341e35c8f28`). Remediation is restricted to gaps reported by the unchanged lab assessor. **Latest assessment: 10 IMPLEMENTED, 0 NOT-CONFIGURED, 0 UNKNOWN**, at **2026-10-30 16:26:09 UTC**. Teams Global meeting-policy read access was restored after supported delegated device-code authentication; the direct read and subsequent unchanged assessor both verified controls 7-9. The earlier 15:26:24 UTC 7/0/3 result remains historical evidence of a read failure, not a configuration reversal. The complete fresh generated report was read without editing it. No tenant settings, roles, exclusions or modules were changed to restore access. Registration and live-workflow limitations remain below.

Baseline assessed at **2026-10-30 13:37:03 UTC**: **0 IMPLEMENTED, 9 NOT-CONFIGURED, 1 UNKNOWN**. The complete generated report and its JSON snapshot were read. Snapshot: `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-133703499Z.json`. All ten snapshot objects identify the expected tenant and assessment time.

Assessor SHA256 before execution: `6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D`. Only this brief is to be manually edited. The assessor alone generates [hardening-results.txt](hardening-results.txt).

## Control Evidence

| # | Formal requirement | Baseline | Latest assessor | Evidence and disposition |
| --- | --- | --- | --- | --- |
| 1 | Mandatory administrative MFA | NOT-CONFIGURED | IMPLEMENTED | Enabled all-users MFA; assessor reports broad coverage verified with only approved exclusions. One of four checked administrative accounts is not reported MFA-capable. |
| 2 | Mandatory MFA, All users and All resources | NOT-CONFIGURED | IMPLEMENTED | Enabled all-users/all-resources policy with sole mandatory MFA grant. Only Isaiah/Nestor excluded; broad coverage verified. Normal operator What If applies MFA. |
| 3 | Block legacy Exchange ActiveSync and Other clients, All users/resources | NOT-CONFIGURED | IMPLEMENTED | Enabled block policy includes both client types. Both What If cases apply the block; real-client dependency testing remains outstanding. |
| 4 | Medium/high sign-in risk, mandatory MFA, every-time primary and secondary authentication | NOT-CONFIGURED | IMPLEMENTED | Enabled matching policy and every-time settings verified. Both risk-threshold simulations passed. Operator P1/P2 provisioned; owner accepted impact for seven reported unregistered users. |
| 5 | High user risk, MFA AND exactly one remediation control, every-time primary and secondary authentication | NOT-CONFIGURED | IMPLEMENTED | Enabled MFA AND passwordChange, not riskRemediation, with required every-time settings. High-risk simulation passed; end-to-end secure password change remains untested. |
| 6 | Disable ordinary-user application self-consent | NOT-CONFIGURED | IMPLEMENTED | Removed the recommended and allow-consent-apps self-consent assignments. No self-consent assignments remain; both owned-resource assignments preserved. Existing grants not revoked. |
| 7 | Global Teams lobby bypass defaults to invited users | NOT-CONFIGURED | IMPLEMENTED | Direct read at 16:25:35 UTC and latest assessor verified `AutoAdmittedUsers = InvitedUsers`. |
| 8 | Global Teams presenters default to organizers/co-organizers only | NOT-CONFIGURED | IMPLEMENTED | Direct read and latest assessor verified `DesignatedPresenterRoleMode = OrganizerOnlyUserOverride`. |
| 9 | Global Teams anonymous meeting joining disabled | NOT-CONFIGURED | IMPLEMENTED | Direct read and latest assessor verified `AllowAnonymousUsersToJoinMeeting = false`. |
| 10 | SSPR scope All | UNKNOWN | IMPLEMENTED | Initially verified None. One All/Save change recorded by service audit; reloaded Properties verified All at 13:48:43 UTC after initial delayed readback. Only then supplied true confirmation. Latest registration: 3/10 registered and capable; seven not, subject to up to 36 hours lag. |

## Safety and Limitations

Isaiah and Nestor were selected from existing accounts under owner authorization; user-reported successful testing is corroborated by portal sign-in, active direct role and registration evidence. Their IDs are excluded in the four enabled policies, explicitly owner-approved and verified in What If; no other exclusions were added. No accounts were created and no directory roles were changed. Ordinary Authenticator MFA is an accepted interim lab measure, not phishing-resistant emergency access. Fresh authentication approval steps were not independently retrieved. The owner confirms private recovery credential custody and replacement of exposed passwords; the assistant neither performed nor independently verified rotation. No passwords, tokens, QR secrets or application credentials are recorded here. Authentication and registration must be completed directly by users. Configured MFA does not prove enrollment or successful sign-in. The owner accepted legacy-authentication blocking and possible risk-related lockouts for the seven reported unregistered lab users.

## Implementation Steps

### 1. Local prerequisite inspection, 2026-10-30 13:35:24 UTC

Executed:

```powershell
Get-Location; $PSVersionTable.PSVersion; Get-FileHash -LiteralPath 'C:\Users\Admin\defend\scripts\assess.ps1' -Algorithm SHA256; Get-Module -ListAvailable Microsoft.Graph.Authentication,Microsoft.Graph.Identity.SignIns,Microsoft.Graph.Identity.Governance,MicrosoftTeams,ExchangeOnlineManagement | Select-Object Name,Version; Get-Date -Format o
```

Result: working directory `C:\Users\Admin\defend`; PowerShell 7.6.6; Graph Authentication, Identity.SignIns and Identity.Governance 2.41.2; MicrosoftTeams 8.0.0. ExchangeOnlineManagement was initially absent. Assessor hash recorded above. No tenant operation in this step.

Read-only file tools inspected the complete attached plan, the assessor's execution/prerequisite section, and the empty brief. A workspace instruction-file search and memory lookup returned no matches. No source files were changed.

### 2. Baseline assessment, completed 2026-10-30 13:37:03 UTC

Executed as the first tenant operation:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$false
```

Result: completed and generated a fresh report and timestamped snapshot. The script installed ExchangeOnlineManagement 3.10.1 for the current user through its built-in prerequisite handling. No installation error was reported. It connected to Graph as `admin@wwlcpx73950877.onmicrosoft.com`, delegated, process scope, expected tenant. Teams output identified the same account and tenant in AzureCloud. WAM emitted a warning that an interactive window may be hidden. No QR or registration prompt was surfaced to the assistant. Broad all-script write consent and automatic Teams application/certificate provisioning were disabled by the supplied parameters. SSPR confirmation remained explicitly false.

The script warned that administrator role coverage could not be evaluated because an assigned role could not be resolved to a built-in template. This is an unresolved advisory, not evidence of successful coverage. All baseline statuses and evidence are preserved above. Complete report and snapshot read immediately after execution; no report content was manually altered.

### 3. Evidence documentation and authoritative guidance

Read the full generated report and snapshot using file tools. Queried Microsoft Learn for disabling application self-consent while preserving owned-resource assignments, and supported Teams meeting-policy parameters. Created this baseline brief with the patch tool. No remediation write has occurred at this point.

### 4. Read-only prerequisites, 2026-10-30 13:37-13:38 UTC

Submitted the following inspection as multiline PowerShell. The tool returned only the first assignment; execution of remaining statements was initially uncertain. The terminal-last-command tool returned no command for the active terminal. Repeated the same inspection in a single `& { ... }` block, with statements separated by semicolons; that retry completed at an inspection start time of 13:38:18 UTC. Both submissions were read-only:

```powershell
$inspectionTime = [datetimeoffset]::UtcNow
$graphContext = Get-MgContext
if ($graphContext.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $graphContext.AuthType -ne 'Delegated') { throw 'Unexpected Graph identity.' }
$graphContext | Select-Object Account,TenantId,AuthType,Scopes | Format-List
$operator = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
$operatorRoles = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($operator.id)'&`$expand=roleDefinition"
$operatorRoles.value | ForEach-Object { [pscustomobject]@{ Role = $_.roleDefinition.displayName; TemplateId = $_.roleDefinition.templateId; Scope = $_.directoryScopeId } } | Format-Table
$authorizationBefore = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'
$authorizationBefore | ConvertTo-Json -Depth 20
$teamsBefore = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop
$teamsBefore | Select-Object Identity,AutoAdmittedUsers,DesignatedPresenterRoleMode,AllowAnonymousUsersToJoinMeeting | Format-List
Get-Command Set-CsTeamsMeetingPolicy | Select-Object Name,Version
$inspectionTime.ToString('o')
```

Result: expected delegated operator and tenant; active direct **Global Administrator**, template `62e90394-69f5-4237-9190-012177145e10`, directory scope `/`. No role was assigned or changed. Teams setter version 8.0.0. Consent includes the two self-consent assignments from the baseline plus `ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team` and `ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-chat`, which must be preserved. Other authorization properties read: email-based subscriptions true; invitations everyone; risky-app consent null; guest role `10dae51f-b6af-4016-8d66-8c2a99b929b3`; blockMsolPowerShell false; allowedToUseSSPR true; email-verified users joining true. Default user permissions for creating security groups, tenants and apps, reading owned-device BitLocker keys, and reading other users were all true. `allowedToUseSSPR` is not evidence of SSPR All scope.

Opened `https://entra.microsoft.com/#view/Microsoft_AAD_IAM/PasswordResetMenuBlade/~/Properties`. Initial sign-in page showed a blocked Azure co-branding frame; later page snapshots showed authentication advancing to **Let's keep your account secure**, requiring another verification method. No portal settings were read or saved. The assistant did not enter passwords, register a method, or capture a QR. Asked the operator about emergency recovery and portal sign-in; response indicated the operator was unavailable and requested autonomous work. This does not establish emergency access or authorize bypassing registration. The operator was notified to complete verification setup and scan a QR directly in Authenticator if that option is selected.

### 5. Durable before-state capture, 2026-10-30 13:38:37 UTC

Executed:

```powershell
& { Get-Date -Format o; (Get-MgContext).Scopes | Sort-Object; $global:consentBefore = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'; $global:meetingBefore = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop; $global:meetingBefore.PSObject.Properties | Where-Object Name -in @('Identity','AutoAdmittedUsers','DesignatedPresenterRoleMode','AllowAnonymousUsersToJoinMeeting') | Select-Object Name,Value | Format-Table }
```

Result: full consent and Global Teams before-state retained in the current PowerShell session. Granted Graph scopes: `AuditLog.Read.All`, `email`, `openid`, `Policy.Read.All`, `profile`, `RoleManagement.Read.Directory`, `SecurityEvents.Read.All`, `User.Read.All`. Authorization write permission is absent. Teams before-values remain exactly those in baseline controls 7-9. No tenant write in this step.

### 6. Teams batch decision, planned before execution

Scope: controls 7-9 only, Global meeting policy. Set lobby `EveryoneInCompany` to `InvitedUsers`, presenter mode `EveryoneUserOverride` to `OrganizerOnlyUserOverride`, anonymous joining true to false. Reuse existing delegated Teams connection, already verified for the expected tenant and administrator. No extra application, credential, license or role is needed for this policy update. No other meeting policy or property is targeted.

Rationale: reduce unsolicited admission and presentation, and prevent unauthenticated participation. Keeping anonymous users in a lobby would not meet the requirement. A pilot policy would not satisfy the required Global default. These are defaults where organizer overrides are supported, not immutable presenter/lobby restrictions. Forwarded invitations can affect invited status. Anonymous attendees will need supported authenticated participation. Policy propagation may delay client behavior; actual meeting behavior is not yet tested.

Rollback, **not executed**: restore only `AutoAdmittedUsers = EveryoneInCompany`, `DesignatedPresenterRoleMode = EveryoneUserOverride`, `AllowAnonymousUsersToJoinMeeting = True` on Global using `Set-CsTeamsMeetingPolicy`, then read back and reassess. A rollback would intentionally restore the original security gaps and requires an explicit operational decision. Planned validation: direct property readback, comparison of all other returned properties against the in-session before-state, then unchanged assessor and full report read before any further configuration batch.

### 7. Teams batch execution and verification, 2026-10-30 13:39:26-13:39:30 UTC

Executed:

```powershell
& { $ErrorActionPreference = 'Stop'; if ((Get-MgContext).TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $null -eq $global:meetingBefore) { throw 'Tenant or before-state verification missing.' }; Get-Date -Format o; Set-CsTeamsMeetingPolicy -Identity Global -AutoAdmittedUsers InvitedUsers -DesignatedPresenterRoleMode OrganizerOnlyUserOverride -AllowAnonymousUsersToJoinMeeting:$false -ErrorAction Stop; $global:meetingAfter = Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop; $global:meetingAfter | Select-Object Identity,AutoAdmittedUsers,DesignatedPresenterRoleMode,AllowAnonymousUsersToJoinMeeting | Format-List; if ($global:meetingAfter.AutoAdmittedUsers -ne 'InvitedUsers' -or $global:meetingAfter.DesignatedPresenterRoleMode -ne 'OrganizerOnlyUserOverride' -or $global:meetingAfter.AllowAnonymousUsersToJoinMeeting -ne $false) { throw 'Teams property readback mismatch.' }; $changedProperties = @(foreach ($property in $global:meetingBefore.PSObject.Properties) { if (($property.Value | ConvertTo-Json -Depth 20 -Compress) -cne ($global:meetingAfter.($property.Name) | ConvertTo-Json -Depth 20 -Compress)) { $property.Name } }); $changedProperties; if (@($changedProperties | Where-Object { $_ -notin @('AutoAdmittedUsers','DesignatedPresenterRoleMode','AllowAnonymousUsersToJoinMeeting') }).Count -gt 0) { throw 'Unexpected Teams property changes detected.' }; Get-Date -Format o }
```

Result: all three target values matched direct readback. Comparing all properties returned by the before/after Teams objects found exactly the three intended changed properties and no others. No rollback or repeat write was performed.

Immediately reran:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$false
```

Result at 13:39:49 UTC: controls **7, 8, 9 IMPLEMENTED**; controls **1-6 NOT-CONFIGURED**; **10 UNKNOWN**. Same tenant and delegated account; existing connections reused. Same unresolved administrative-role coverage advisory. Read the complete regenerated report and complete snapshot `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-133949449Z.json`. All ten objects identify the expected tenant/time. No report manipulation occurred. Teams configuration is verified, but live meeting admission/presentation behavior and client propagation have not been tested.

### 8. Narrow consent authorization, 2026-10-30 13:39-13:40 UTC

After the Teams batch, executed:

```powershell
Connect-MgGraph -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -Scopes 'Policy.ReadWrite.Authorization' -ContextScope Process -NoWelcome -ErrorAction Stop
```

Returned without output or error. Requested only the additional delegated permission needed for control 6, not application permissions or a directory role assignment. Then executed at 13:40:21 UTC:

```powershell
& { Get-Date -Format o; $context = Get-MgContext; $context | Select-Object Account,TenantId,AuthType | Format-List; $context.Scopes | Sort-Object; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com' -or $context.Scopes -notcontains 'Policy.ReadWrite.Authorization') { throw 'Consent write authorization not verified.' }; $global:consentBefore = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'; $global:consentBefore.defaultUserRolePermissions | ConvertTo-Json -Depth 10 }
```

Result: expected delegated administrator and tenant verified, `Policy.ReadWrite.Authorization` present alongside prior scopes. Refreshed before-state retains the four original consent assignments and other user permissions. No consent configuration write yet.

### 9. Consent batch decision, planned before execution

Control 6: remove the two `ManagePermissionGrantsForSelf.*` assignments from `authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned`, preserving both existing `ManagePermissionGrantsForOwnedResource.*` assignments and every unrelated authorization field. Use the supported Graph v1.0 nested PATCH shape, not a replacement of the entire authorization policy. Conditional Access and SSPR remain untouched.

Rationale: disable ordinary-user self-consent, including limited consent to selected apps, as explicitly required by the lab. Verified-publisher-only consent would not satisfy that requirement. Existing consent grants are not revoked, so this does not remediate already-granted malicious access. New app requests can require administrative approval and cause support demand. No admin consent workflow is created, as that was not a reported gap. Teams/chat owned-resource consent remains available under its existing policies.

Rollback, **not executed**: PATCH the same nested property back to the exact four assignments captured in step 4/8. Preserve unrelated fields; read back and reassess. This restores ordinary-user self-consent and should occur only on an explicit operational decision. Planned verification: no self-consent assignments remain, the two owned-resource assignments match, and all other top-level/nested properties match before-state; then rerun assessor and read the complete report.

### 10. Consent execution and verification, 2026-10-30 13:41:08-13:41:11 UTC

Executed:

```powershell
& { $ErrorActionPreference = 'Stop'; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Scopes -notcontains 'Policy.ReadWrite.Authorization' -or $null -eq $global:consentBefore) { throw 'Consent prerequisites missing.' }; Get-Date -Format o; $retainedAssignments = @($global:consentBefore.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Where-Object { $_ -notlike 'ManagePermissionGrantsForSelf.*' }); $body = @{ defaultUserRolePermissions = @{ permissionGrantPoliciesAssigned = $retainedAssignments } } | ConvertTo-Json -Depth 10; Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -Body $body -ContentType 'application/json' -ErrorAction Stop; $global:consentAfter = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy'; $global:consentAfter.defaultUserRolePermissions | ConvertTo-Json -Depth 10; if ((@($retainedAssignments | Sort-Object) -join '|') -cne (@($global:consentAfter.defaultUserRolePermissions.permissionGrantPoliciesAssigned | Sort-Object) -join '|')) { throw 'Consent assignment readback mismatch.' }; foreach ($propertyName in $global:consentBefore.Keys) { if ($propertyName -ne 'defaultUserRolePermissions' -and ($global:consentBefore[$propertyName] | ConvertTo-Json -Depth 20 -Compress) -cne ($global:consentAfter[$propertyName] | ConvertTo-Json -Depth 20 -Compress)) { throw "Unrelated authorization property changed: $propertyName" } }; foreach ($propertyName in $global:consentBefore.defaultUserRolePermissions.Keys) { if ($propertyName -ne 'permissionGrantPoliciesAssigned' -and ($global:consentBefore.defaultUserRolePermissions[$propertyName] | ConvertTo-Json -Depth 20 -Compress) -cne ($global:consentAfter.defaultUserRolePermissions[$propertyName] | ConvertTo-Json -Depth 20 -Compress)) { throw "Unrelated default-user property changed: $propertyName" } }; 'Consent readback and unrelated-property checks passed.'; Get-Date -Format o }
```

Result: PATCH succeeded. Readback retained only the chat and team owned-resource assignments; service returned them in reversed order, with unchanged membership. No self-consent assignment remained. Every other before-state top-level/default-user property compared equal. No rollback needed; no existing grants revoked.

Immediately executed the unchanged assessor a third time:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$false
```

Result at 13:41:36 UTC: **controls 6-9 IMPLEMENTED; 1-5 NOT-CONFIGURED; 10 UNKNOWN**. Read complete report and JSON snapshot `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-134136086Z.json`. All objects match expected tenant/time. The assessor reused the delegated Graph context, which still included the explicitly requested narrow write scope; `ConsentForAllScripts:$false` avoids requesting broad write scopes, not stripping scopes already granted. No extra tenant write by the assessment was observed.

### 11. Integrity check, 2026-10-30 13:41:48 UTC

Executed:

```powershell
& { Get-Date -Format o; $hash = Get-FileHash -LiteralPath 'C:\Users\Admin\defend\scripts\assess.ps1' -Algorithm SHA256; $hash | Format-List; if ($hash.Hash -ne '6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D') { throw 'Assessor integrity mismatch.' }; Get-Item -LiteralPath '.\hardening-results.txt' | Select-Object FullName,Length,LastWriteTimeUtc | Format-List; if (Test-Path -LiteralPath '.git') { git status --short } }
```

Hash matched the pre-execution value. Report length 1,721 bytes, modified 13:41:36 UTC, matching assessment time. The final `git status --short` failed because `git` was not recognized on PATH. No Git changes, installs or workaround were attempted; repository-wide diff verification is unavailable. Tool action history shows only this brief was manually edited; report and snapshots were generated by the unchanged assessor. This limitation does not invalidate the successful file-hash verification.

### 12. SSPR portal inspection and licensing, 2026-10-30 13:41-13:43 UTC

A browser snapshot showed **Authenticator app added** on My Sign-Ins. This occurred outside assistant tool actions. The operator subsequently explicitly confirmed scanning the QR and completing mobile Authenticator setup. The assistant neither enrolled the method nor accessed its secret. This establishes reported registration, not an independent emergency-recovery test.

Navigated again to Entra Password reset Properties. Loaded page identified `admin@wwlcpx73950877.onmicrosoft.com`, Contoso, tenant GUID `7a9b5e57-db07-4525-896c-0341e35c8f28`. **None** was checked; **Save** disabled, proving an unchanged loaded before-state. Thus control 10's reported UNKNOWN was investigated and found noncompliant. Browser console emitted header/CSS and one HTTP 400 diagnostic, but the Properties control loaded and exposed its persisted value. No setting saved during inspection.

Requested read-only licensing scope:

```powershell
Connect-MgGraph -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -Scopes 'LicenseAssignment.Read.All' -ContextScope Process -NoWelcome -ErrorAction Stop
```

Connection returned without output/error. Executed at 13:42:50 UTC:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Scopes -notcontains 'LicenseAssignment.Read.All') { throw 'Licensing read context mismatch.' }; $skus = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus'; $skus.value | ForEach-Object { [pscustomobject]@{ Sku = $_.skuPartNumber; Status = $_.capabilityStatus; EnabledUnits = $_.prepaidUnits.enabled; ConsumedUnits = $_.consumedUnits; IdentityPlans = @($_.servicePlans | Where-Object servicePlanName -match 'AAD_PREMIUM|SSPR' | Select-Object servicePlanName,servicePlanId,provisioningStatus) } } | ConvertTo-Json -Depth 10; $global:enabledMemberPlans = @(); $nextPage = 'https://graph.microsoft.com/v1.0/users?$select=id,accountEnabled,userType,assignedPlans,onPremisesSyncEnabled&$top=999'; while ($nextPage) { $page = Invoke-MgGraphRequest -Method GET -Uri $nextPage; $global:enabledMemberPlans += @($page.value | Where-Object { $_.accountEnabled -eq $true -and $_.userType -eq 'Member' }); $nextPage = $page.'@odata.nextLink' }; $premiumPlanIds = @($skus.value.servicePlans | Where-Object { $_.servicePlanName -in @('AAD_PREMIUM','AAD_PREMIUM_P2') -and $_.provisioningStatus -eq 'Success' } | ForEach-Object servicePlanId); [pscustomobject]@{ EnabledMembers = $global:enabledMemberPlans.Count; MembersWithEnabledEntraPremium = @($global:enabledMemberPlans | Where-Object { @($_.assignedPlans | Where-Object { $_.servicePlanId -in $premiumPlanIds -and $_.capabilityStatus -eq 'Enabled' }).Count -gt 0 }).Count; SyncedMembers = @($global:enabledMemberPlans | Where-Object onPremisesSyncEnabled -eq $true).Count } | Format-List }
```

Result: enabled `MICROSOFT_365_E7_NO_TEAMS`, 15 units, 9 consumed; AAD_PREMIUM and AAD_PREMIUM_P2 service plans successfully provisioned. Other returned enabled SKUs: VIRTUAL_AGENT_USL (15/10), Power_Virtual_Agents (1/0), Microsoft_Teams_Enterprise_New (15/10), POWERAPPS_DEV (10,000/1), units/consumed respectively. Ten enabled members, nine with enabled Entra Premium plans, zero synced members. No licenses purchased or assigned.

Follow-up at 13:43:01 UTC:

```powershell
& { Get-Date -Format o; $operator = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'; $withoutPremium = @($global:enabledMemberPlans | Where-Object { @($_.assignedPlans | Where-Object { $_.servicePlanId -in @('41781fb2-bc02-4b7c-bd55-b576c07bb09d','eec0eb4f-6444-4f95-aba0-50c24d67f998') -and $_.capabilityStatus -eq 'Enabled' }).Count -eq 0 }); [pscustomobject]@{ MembersWithoutPremium = $withoutPremium.Count; OnlyUnlicensedMemberIsCurrentGlobalAdministrator = ($withoutPremium.Count -eq 1 -and $withoutPremium[0].id -eq $operator.id) } | Format-List }
```

Result: the only member lacking Premium is the current Global Administrator. Microsoft documentation and the portal describe administrator SSPR as independently enabled by default; `allowedToUseSSPR` was already true. The proposed end-user scope change therefore benefits nine licensed non-operator members and does not enable a new administrator reset capability. This does not establish Premium licensing for the administrator or entitlement for future risk/CA policies covering that account. License compliance and changes in future membership remain the tenant owner's responsibility.

A second request for approved/tested emergency access received the same operator-unavailable response. No recovery identity was designated and no Conditional Access enforcement is authorized by that response.

### 13. SSPR decision, planned before execution

Change only Password reset > Properties > Self service password reset enabled from **None** to **All**, using the supported portal. Scope All is explicitly required; Selected would not satisfy the lab. Global Administrator role, expected tenant and licensed end-user population are verified. This enables self-recovery availability; it does not register methods, guarantee reset success, or prove risk-remediation readiness. No synced members were found, so password writeback is not a dependency for this current enabled-member population. No authentication-method, registration, notification, writeback or administrator-reset setting will be changed.

Rollback, **not executed**: return this same property to **None**, Save, reopen Properties and reassess. This removes ordinary-user self-reset availability and restores the original gap. Validation: save acknowledgement, reload persisted Properties showing All, then run the unchanged assessor with `SsprAllScopeConfirmed:$true` only after that independent readback. The confirmation parameter is evidence of an observed setting, not a mechanism for changing SSPR.

### 14. SSPR write attempt and conflicting persistence validation, 2026-10-30 13:44 UTC

Using the same shared browser page and verified tenant, clicked **All** (radio reference e215), then **Save** (e175), once each. The save response showed All checked while controls were disabled and notification **Saving password reset policy**. A subsequent page read showed **Password reset policy saved / Changes to password reset policy were saved successfully**. No other portal property was edited.

Reloaded Properties. A focused read-only Playwright query obtained the radiogroup accessibility snapshot, account label, URL, Save disabled state, and UTC timestamp. At **13:44:46.293 UTC**, scope was **None**, Save disabled, same operator/tenant. Repeated only the focused read at **13:44:53.598 UTC**: still None, no alert, Save disabled. Thus a success toast did not establish persistence. No second write or rollback was attempted; the observed scope already matched the original None value. A delayed backend effect or portal defect cannot be excluded; root cause is not established. Do not treat this as an implemented control or an intentionally completed rollback.

### 15. Fourth assessment and final readback, 2026-10-30 13:46 UTC

Executed after the failed SSPR readback, deliberately retaining false confirmation:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$false
```

Result at **13:46:03.3599727 UTC**: **4 IMPLEMENTED (6-9), 5 NOT-CONFIGURED (1-5), 1 UNKNOWN (10)**. Complete generated report and complete snapshot read: `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-134603359Z.json`. All ten objects match tenant/time. Same administrator role-resolution warning. SSPR registration/capability remains 0/10; this lagging report does not negate the operator's confirmed Authenticator setup and does not prove MFA enforcement or usable SSPR. No reset or live Teams meeting was tested.

Reloaded Properties once more, without changing anything. At **13:46:42.677 UTC**, focused browser readback again showed **None**, Save disabled, no alert, expected tenant/operator. These bounded read-only checks did not verify All. No unsupported API, report manipulation or guessed confirmation was used to bypass the discrepancy.

In parallel with the final reload, executed the final local integrity check at **13:46:35.8735639 UTC**:

```powershell
& { Get-Date -Format o; $hash = Get-FileHash -LiteralPath 'C:\Users\Admin\defend\scripts\assess.ps1' -Algorithm SHA256; $hash | Format-List; if ($hash.Hash -ne '6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D') { throw 'Assessor integrity mismatch.' } }
```

Result: exact baseline SHA256 match. Only this brief was manually edited using patches; document diagnostics were checked after edits. Read-only file/browser tools reviewed generated evidence and relevant documentation. No remediation script, account, role assignment, license assignment, Conditional Access policy, exclusion or application credential was created. All rollbacks remain **not executed**. Existing delegated sessions remain available for the operator; no forced sign-out or permission revocation was performed.

### 16. PowerShell audit investigation following operator suggestion, 2026-10-30 13:47:54 UTC

The operator suggested Azure PowerShell instead of browser checks. Searched current Microsoft Learn guidance for a supported exact None/Selected/All scope command. The results documented the portal workflow and separate administrator `allowedToUseSSPR` property, not an equivalent supported scope getter. No legacy module was installed and no undocumented endpoint used. Used the already connected Graph PowerShell session and existing `AuditLog.Read.All` permission for a bounded audit investigation:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Scopes -notcontains 'AuditLog.Read.All') { throw 'Audit read context mismatch.' }; $auditEvents = @(); $nextPage = 'https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?$filter=activityDateTime%20ge%202026-10-30T13:43:00Z%20and%20activityDateTime%20le%202026-10-30T13:47:00Z&$top=100'; while ($nextPage) { $page = Invoke-MgGraphRequest -Method GET -Uri $nextPage; $auditEvents += @($page.value); $nextPage = $page.'@odata.nextLink' }; [pscustomobject]@{ AuditWindowStartUtc = '2026-10-30T13:43:00Z'; AuditWindowEndUtc = '2026-10-30T13:47:00Z'; Count = $auditEvents.Count } | Format-List; $auditEvents | ForEach-Object { [pscustomobject]@{ Time = $_.activityDateTime; Activity = $_.activityDisplayName; Service = $_.loggedByService; Result = $_.result; Reason = $_.resultReason; CorrelationId = $_.correlationId; ChangedProperties = @($_.targetResources.modifiedProperties) } } | ConvertTo-Json -Depth 12 }
```

Returned three successful events:

- **13:44:18.5173343 UTC: Update SSPR Settings**, Self-service Password Management, reason `SSPR Settings modified.`, correlation `241f04e1-5e2b-4e42-a19f-14a590d5c00b`. `EnablementForUsers` changed **None -> All**; `RestrictSelfServePasswordResetAccess` changed null -> False.
- **13:44:18.4909517 UTC: Update service principal**, Core Directory, correlation `2a6c07cb-9ce2-4c0b-bff7-906ddf7edf03`, no detailed changed properties returned.
- **13:44:18.1676038 UTC: Add policy**, Core Directory, correlation `7208ae36-0f5b-4d34-9374-f7f5397de154`, DisplayName `Password Management`, PolicyType `PasswordManagement`, actor/service principal name `93625bc8-bfe2-437a-97e0-3d0060024faa` / `https://passwordreset.microsoftonline.com/`.

These are service-recorded effects associated in time with the single supported portal save, not additional assistant-issued policy or service-principal commands. There was no rollback event in the returned time window. Audit ingestion delay and the finite query window limit that observation. This evidence revises the earlier uncertainty: **the SSPR service recorded a successful None-to-All change**. Historical audit evidence is not a current-state getter; the conflicting fresh Properties reads still require reconciliation before declaring verified current All. Reloaded Properties again in response to this new evidence; no repeat write or scope-confirmation override.

### 17. SSPR discrepancy resolved and final assessment, 2026-10-30 13:48-13:49 UTC

At **13:48:43.755 UTC**, the focused read-only browser query after the reload returned **All checked**, None/Selected unchecked, Save disabled, and the same expected operator/tenant. This reconciles the audit result with current persisted portal state. The initial readback discrepancy is resolved without a second write; the sequence is consistent with propagation or read-side delay, but its precise underlying cause was not diagnosed. Historical steps 14-16 describe the uncertainty at those times, not the final state.

Only after that independent readback, ran the unchanged assessor with explicit true confirmation:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$true
```

Result at **13:49:07.2888383 UTC: 5 IMPLEMENTED (6-10), 5 NOT-CONFIGURED (1-5), 0 UNKNOWN**. Read the complete generated report and complete snapshot `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-134907288Z.json`; all ten objects match tenant/time. Graph and Teams reused the expected delegated account. Administrator role-coverage warning remains unresolved and no Conditional Access policies were changed.

Latest SSPR registration evidence now reports **1/10 registered and capable, 9/10 not registered/capable**, with no missing data and up to 36 hours possible reporting lag. The aggregate does not identify which account changed. Scope All is verified; complete enrollment and successful end-to-end recovery are not. The assessor's literal evidence says confirmation is recorded "by the script default"; this run actually supplied the explicit true argument shown above after independent observation. Neither script nor report was edited to change that wording.

Final documentation update records all writes, connection requests, diagnostic commands, retries, results and limitations. Document diagnostics are checked after the patch. No further tenant action, permission request or rollback is planned while the recovery gate remains unresolved.

### 18. Renewed request to address remaining gaps, 2026-10-30

The operator requested proceeding with the five remaining gaps in the attached 13:49:07 UTC report. Requested approved emergency-account UPNs/object IDs and independent sign-in/administrative-capability test evidence, explicitly excluding secrets. The question tool returned that the operator was unavailable and requested autonomous work; it supplied no account identifiers, approval or test evidence. This does not satisfy or supersede the original emergency-access prerequisite.

Reviewed the existing remaining gates. No tenant read/write command, new assessment, policy staging, account creation, role/license assignment or rollback was performed during this renewed attempt. Only this action record was added; document diagnostics checked afterward. The attached assessment remains the latest evidence, not a newly measured tenant state. Controls 1-5 remain blocked pending recovery verification and the other readiness gates below. Do not designate an arbitrary administrator as an emergency account or assume the current session proves independent recovery.

### 19. Credentials supplied with renewed enforcement request, 2026-10-30

The operator supplied the existing administrator/tenant identifiers and application details with passwords and an application secret, asking to configure controls 1-5. Secret values are deliberately omitted from this record and were not sent to authentication tools, commands or files. These details do not identify an approved independent emergency account or establish successful recovery testing. The original prohibition on using application secrets and the emergency-access prerequisite remain in effect; no application authentication or tenant configuration change was attempted.

Advised the operator to treat the disclosed passwords and application secret as exposed and arrange rotation through the tenant/lab owner, preserving recovery access and coordinating updates to dependent applications. No credential rotation, revocation or application modification was performed under this task. Requested next decision: identify an existing approved recovery account and independent test results, or explicitly authorize a separately scoped emergency-access setup if none exists. No secrets are needed in the response. Updated this brief and checked document diagnostics; the latest assessment remains the 13:49:07 UTC run.

### 20. Authorized candidate selection and read-only checks, 2026-10-30 14:02:16 UTC

The operator authorized choosing existing accounts other than `admin@WWLCPx73950877.onmicrosoft.com`, following the explicit discussion of dedicating two accounts to emergency access and assigning Global Administrator if necessary. Selected Isaiah Langer and Nestor Wilke for verification. This supersedes the need for the operator to nominate account identifiers; it does not establish secured credentials, independent authentication or tested recovery. The operator subsequently stated they have the user passwords. No password was requested or used by the assistant.

Consulted official Microsoft Graph PowerShell user-query examples and read the nearby action log. Executed this read-only inspection through the existing delegated session:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com') { throw 'Unexpected delegated context.' }; $uri = 'https://graph.microsoft.com/v1.0/users?$filter=displayName%20eq%20%27Isaiah%20Langer%27%20or%20displayName%20eq%20%27Nestor%20Wilke%27&$select=id,displayName,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,lastPasswordChangeDateTime,signInActivity'; $global:recoveryCandidates = @((Invoke-MgGraphRequest -Method GET -Uri $uri).value); if ($global:recoveryCandidates.Count -ne 2) { throw 'Expected exactly two candidate users.' }; foreach ($candidate in $global:recoveryCandidates) { if ($candidate.userPrincipalName -ieq $context.Account -or $candidate.userType -ne 'Member' -or $candidate.onPremisesSyncEnabled -eq $true -or $candidate.accountEnabled -ne $true) { throw 'Candidate does not meet basic eligibility.' }; $roleUri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($candidate.id)'&`$expand=roleDefinition"; $roles = Invoke-MgGraphRequest -Method GET -Uri $roleUri; [pscustomobject]@{ Id = $candidate.id; Name = $candidate.displayName; UPN = $candidate.userPrincipalName; Enabled = $candidate.accountEnabled; UserType = $candidate.userType; Synced = $candidate.onPremisesSyncEnabled; PasswordLastChanged = $candidate.lastPasswordChangeDateTime; SignInActivity = $candidate.signInActivity; DirectRoles = @($roles.value | ForEach-Object { $_.roleDefinition.displayName }) } | ConvertTo-Json -Depth 8 }; $fidoPolicy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'; $fidoPolicy | Select-Object id,state,includeTargets,excludeTargets | ConvertTo-Json -Depth 8 }
```

Result, expected tenant/operator verified:

| Candidate | Object ID | Readback |
| --- | --- | --- |
| `IsaiahL@WWLCPx73950877.OnMicrosoft.com` | `3410ee51-2c02-4829-843a-e9f44757d8f3` | Enabled Member; onPremisesSyncEnabled null; existing direct Global Administrator assignment; password last changed 2026-10-30 00:45:30 UTC; signInActivity null. |
| `NestorW@WWLCPx73950877.OnMicrosoft.com` | `e13ea4a7-a05a-4442-8864-0091a0e1244b` | Enabled Member; onPremisesSyncEnabled null; existing direct Global Administrator assignment; password last changed 2026-10-30 00:45:32 UTC; signInActivity null. |

Both use the tenant's onmicrosoft.com domain and are not reported synchronized. Null sign-in activity does not prove an account is unused. Existing Global Administrator assignments were discovered, not created by this task; permanent assignment duration was not verified. No additional role assignment is needed at this stage. FIDO2 policy is enabled, includes all_users with allowed passkey profile `00000000-0000-0000-0000-000000000001`, has no exclusions, and does not require registration. This confirms policy availability, not either candidate's enrolled methods or recovery capability.

Advised keeping passwords out of chat, privately replacing any credentials that match the previously disclosed password, registering independently available phishing-resistant recovery authentication, and testing each account in a separate private sign-in session. Existing active administrator access must be retained while testing. The operator must perform credential entry and physical authenticator interactions directly. No credential, authentication-method policy, role, account or Conditional Access change was made. Only this brief was edited and its diagnostics checked. No new assessment was run because no tenant setting was changed.

### 21. Authenticator passkey preparation, 2026-10-30 14:07 UTC

The operator selected passkeys in Microsoft Authenticator and requested PowerShell execution with interactive sign-in. Consulted Microsoft Learn registration and enablement guidance and Graph PowerShell examples. Authenticator passkey creation requires user interaction on a compatible phone; Graph PowerShell sign-in alone does not register a phone passkey. Recovery-device independence remains unconfirmed.

At 14:07:35 UTC, ran the following read-only check in the existing delegated administrator session:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com') { throw 'Unexpected delegated context.' }; $policy = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'; $policy | ConvertTo-Json -Depth 20; [pscustomobject]@{ EdgeAvailable = (Test-Path "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe") } | ConvertTo-Json }
```

The expected context was verified. FIDO2 and self-service registration are enabled for all users, without exclusions. Default profile `00000000-0000-0000-0000-000000000001` permits deviceBound and synced passkeys, disables attestation enforcement, and has no enforced AAGUID restrictions. These settings permit Authenticator device-bound passkeys without a policy write; they do not prove phone compatibility, registration or successful authentication. Edge executable was found.

At 14:07:41 UTC, executed:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; Start-Process -FilePath "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" -ArgumentList @('--inprivate', '--new-window', 'https://mysignins.microsoft.com/security-info'); Write-Output 'Requested Edge InPrivate Security info window. Operator must verify IsaiahL account before registering; existing admin session left unchanged.' }
```

The launch command completed successfully; the external window contents and account were not inspected. Directed the operator to sign in as Isaiah first, verify the account identity, and choose Add sign-in method > Passkey in Microsoft Authenticator. Requirements include Android 14+ or iOS 17+, current Authenticator, screen lock, passkey-provider configuration and MFA bootstrap. For cross-device passkey authentication, Bluetooth and internet connectivity are required on both devices. If registration requires an unavailable MFA method, stop and report the non-secret prompt; no Temporary Access Pass was created or authentication method reset performed.

After Isaiah completes registration and a fresh passkey sign-in plus administrative-access test, all InPrivate windows must be closed before starting a new private session for Nestor to avoid sharing the prior private session. The working administrator session must remain open. No secrets were requested, supplied to commands or stored. No new script file, policy write, role change or assessment run occurred; assessor and generated report remain untouched. Registration and independent recovery testing are pending user action. Only this brief was edited for this step.

### 22. Requested passkey verification; authentication canceled, 2026-10-30

The operator supplied a Security info screenshot for Isaiah and stated that the Authenticator registration was a passkey, requesting PowerShell verification. The screenshot labels the visible method as push MFA, but no final conclusion about passkey registration was drawn without direct Graph verification. Consulted Microsoft Learn FIDO2 list API permissions and PowerShell examples.

At 14:14:41 UTC, executed this context-only check:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com') { throw 'Unexpected delegated context.' }; $context | Select-Object TenantId,Account,AuthType,Scopes | ConvertTo-Json -Depth 4 }
```

The expected delegated administrator context was present, but no authentication-method read scope was available. Requested the documented passkey-specific read scope, not authentication-method write access, using this command:

```powershell
& { $ErrorActionPreference = 'Stop'; Connect-MgGraph -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -Scopes 'UserAuthMethod-Passkey.Read.All' -ContextScope Process -NoWelcome; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com') { throw 'Unexpected delegated context; no user query executed.' }; Get-Date -Format o; $response = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users/3410ee51-2c02-4829-843a-e9f44757d8f3/authentication/fido2Methods'; $methods = @($response.value); [pscustomobject]@{ User = 'IsaiahL@WWLCPx73950877.onmicrosoft.com'; PasskeyCount = $methods.Count; HasNextPage = [bool]$response.'@odata.nextLink'; Passkeys = @($methods | Select-Object displayName,model,aaGuid,createdDateTime,attestationLevel) } | ConvertTo-Json -Depth 6 }
```

Connect-MgGraph failed with `InteractiveBrowserCredential authentication failed: User canceled authentication.` The command exited with code 1 before the user query; no passkey count or metadata was retrieved. Registration remains unverified, not confirmed absent. No retry was made after cancellation, no authentication methods or tenant policies were changed, and no successful new consent is claimed. A subsequent attempt requires interactive administrator authentication and a fresh context check. Assessor and generated report were untouched; only this brief was edited.

### 23. Successful passkey verification retry, 2026-10-30 14:18:12 UTC

The operator authorized reopening the interactive sign-in prompt. Re-executed the exact Connect-MgGraph and FIDO2 query command recorded in step 22, requesting `UserAuthMethod-Passkey.Read.All` with Process context. Authentication succeeded, and the command verified the expected tenant, delegated authentication and administrator account before querying Isaiah's authentication methods. PowerShell emitted an informational WAM warning that the sign-in window might be hidden behind other windows; the command nevertheless completed successfully with exit code 0.

The direct Graph v1.0 response for `/users/3410ee51-2c02-4829-843a-e9f44757d8f3/authentication/fido2Methods` produced:

```json
{
	"User": "IsaiahL@WWLCPx73950877.onmicrosoft.com",
	"PasskeyCount": 0,
	"HasNextPage": false,
	"Passkeys": []
}
```

No FIDO2 passkey was registered for Isaiah at this check, and there was no additional results page. This resolves the interrupted verification in step 22; it does not test push MFA or establish recovery readiness. The earlier screenshot showed an Authenticator push MFA entry. The operator still needs to complete passkey registration on a supported device and independently test it. Nestor was not queried in this step. No authentication methods, accounts, roles or Conditional Access policies were modified. The read-only permission was requested through interactive delegated authentication, not application credentials. Only this brief was edited; the assessor and generated report were untouched, and no new assessment was run.

### 24. Interim Authenticator MFA selected, 2026-10-30

The operator chose to proceed with ordinary MFA for now because their available Android device cannot currently support the desired Authenticator passkey flow. Passkey registration is deferred rather than required as the immediate next step. Microsoft documentation specifies Android 14+ and recommends Android 15 when the device cannot enable Authenticator as a passkey provider on Android 14; this does not establish compatibility of the operator's particular device.

Accepted Authenticator MFA for interim lab recovery-account setup and testing. Push MFA is not phishing-resistant and is not equivalent to Microsoft's recommended passkey or certificate-based emergency-access configuration. This choice does not establish independent recovery, waive the pre-enforcement recovery test, or resolve licensing and affected-user readiness gates. If the working administrator and both recovery accounts rely solely on the same phone, losing that phone remains a shared recovery failure.

Next operator actions: preserve the working administrator session; verify a fresh password-plus-Authenticator MFA sign-in and Entra administrative access for Isaiah; register and independently test MFA for Nestor using a separate fresh private session; report account, test outcome and recovery-device independence without passwords or codes. Retain existing authentication methods. Privately replace any credentials matching those previously disclosed before relying on them for recovery. A registration entry or existing browser session alone does not prove a fresh MFA test.

No tenant commands or writes were performed for this decision. Only this brief was updated. The last direct check still found zero Isaiah passkeys, and the last assessment remains five implemented controls and five not configured. Conditional Access enforcement remains paused pending tested recovery and the other recorded gates.

### 25. Requested private browser launch, 2026-10-30 14:28:52 UTC

At the operator's request, executed:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; Start-Process -FilePath "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" -ArgumentList @('--inprivate', '--new-window', 'https://entra.microsoft.com/'); Write-Output 'Requested Edge InPrivate window for Entra administration. Existing InPrivate windows may share sign-in state; normal browser session was not closed.' }
```

The command completed successfully with exit code 0. External window contents and account identity were not inspected, and no fresh MFA or administrative-access test is claimed. Existing InPrivate windows can share authentication state; a new window alone does not guarantee a fresh sign-in. The working administrator session was not closed. No tenant settings were changed. Only this brief was edited; the assessor and generated report remain untouched.

### 26. Operator-reported Isaiah portal access, 2026-10-30

Following the private-browser launch and sign-in instructions for Isaiah, the operator reported completion and then stated, "yes, it did load successfully" in response to a question about password-plus-Authenticator approval and Entra administration access. Recorded successful portal loading as operator-reported evidence, not independently observed browser or sign-in-log evidence. The reply did not separately describe a fresh MFA challenge or answer whether the recovery authenticator uses the normal administrator's phone. No administrative operation, recovery-device independence, Nestor test or complete recovery readiness is established by this reply. No tenant command or setting change occurred; only this brief was updated. Conditional Access enforcement remains paused pending the recorded gates.

### 27. Operator-confirmed separate recovery phone, 2026-10-30

The operator answered "separate phone" when asked whether the recovery accounts use the normal administrator's phone or a separate phone. Recorded operator confirmation that the recovery phone is separate from the normal administrator's device. This resolves the previously unanswered device-separation question; it does not establish separate devices for each recovery account, credential custody, permanent role assignment, or completion of Nestor's fresh MFA and administrative-access test. Earlier entries describing device independence as unconfirmed are historical. No tenant command or setting change occurred; only this brief was updated.

### 28. Automated recovery evidence checks, 2026-10-30 14:45-14:53 UTC

The operator confirmed Nestor's requested sign-in test had already succeeded and requested PowerShell verification to reduce manual work. Recorded this as operator confirmation of the requested password-plus-Authenticator and portal-access test. The previously confirmed separate recovery phone remains operator-reported evidence. Consulted Microsoft Learn Graph sign-in, authentication-detail and role-schedule documentation and PowerShell examples.

At 14:45:59 UTC, checked `Get-MgContext`, verifying the expected tenant, delegated authentication and administrator account. Existing scopes included AuditLog.Read.All and RoleManagement.Read.Directory; no new consent was initially needed. At 14:46:21 UTC, queried both accounts' sign-in histories and role schedules. The following equivalent reconstruction records the query structure, not a verbatim terminal transcript:

```powershell
& { $ErrorActionPreference = 'Stop'; Get-Date -Format o; $context = Get-MgContext; if ($context.TenantId -ne '7a9b5e57-db07-4525-896c-0341e35c8f28' -or $context.AuthType -ne 'Delegated' -or $context.Account -ne 'admin@wwlcpx73950877.onmicrosoft.com') { throw 'Unexpected delegated context.' }; $global:recoveryVerification = @(); foreach ($candidate in @(@{ Name = 'Isaiah'; Id = '3410ee51-2c02-4829-843a-e9f44757d8f3' }, @{ Name = 'Nestor'; Id = 'e13ea4a7-a05a-4442-8864-0091a0e1244b' })) { $filter = [uri]::EscapeDataString("userId eq '$($candidate.Id)' and createdDateTime ge 2026-10-30T13:00:00Z"); $uri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter&`$top=100"; $signIns = @(); do { $page = Invoke-MgGraphRequest -Method GET -Uri $uri; $signIns += @($page.value | Select-Object id,createdDateTime,appDisplayName,resourceDisplayName,isInteractive,authenticationRequirement,status,authenticationDetails); $uri = $page.'@odata.nextLink' } while ($uri); $roleFilter = [uri]::EscapeDataString("principalId eq '$($candidate.Id)'"); $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$filter=$roleFilter&`$expand=roleDefinition"; $roles = @(); do { $page = Invoke-MgGraphRequest -Method GET -Uri $uri; $roles += @($page.value | ForEach-Object { [pscustomobject]@{ Role = $_.roleDefinition.displayName; RoleTemplate = $_.roleDefinition.templateId; AssignmentType = $_.assignmentType; MemberType = $_.memberType; DirectoryScopeId = $_.directoryScopeId; Start = $_.startDateTime; End = $_.endDateTime } }); $uri = $page.'@odata.nextLink' } while ($uri); $record = [pscustomobject]@{ Name = $candidate.Name; SignInCount = $signIns.Count; SignIns = $signIns; Roles = $roles }; $global:recoveryVerification += $record; $record | ConvertTo-Json -Depth 9 } }
```

Both paginated collections were exhausted for each account. Five sign-in events were returned per account:

| Account | Successful portal sign-in (UTC) | Event ID | MFA evidence in v1.0 response |
| --- | --- | --- | --- |
| Isaiah | 14:28:54 | 2827da64-aa42-4608-b3ff-a985a2726e00 | Azure Portal / Azure Resource Manager; errorCode 0; MFA requirement satisfied by claim in the token. This is reused MFA evidence, not proof of a new approval at this event. |
| Nestor | 14:30:38 | bab4a94d-6f08-4fc6-b776-a405f6b17d00 | Azure Portal / Azure Resource Manager; errorCode 0; no additional MFA detail at this event. Later successful events at 14:36:43 and 14:37:33 report an MFA claim in the token. |

Nestor's later MFA-claim events were `2109ec59-2754-446d-a4cd-751b65c46600` (Microsoft Account Controls V2) and `a3bb78bc-7127-4437-8610-9715553e3d00` (Microsoft Authentication Broker). Isaiah also had successful My Signins/My Profile events at 14:09:13, 14:16:56 and 14:19:16; the latter two reported MFA claims. His 14:09:10 event returned 50140, identified by Graph as the expected Keep me signed in interruption, followed by success. No authentication method details were exposed by the v1.0 response. Absence of those fields is not proof that MFA was absent.

For both accounts, the active role schedule returned Global Administrator, template `62e90394-69f5-4237-9190-012177145e10`, assignmentType Assigned, memberType Direct, directoryScopeId `/`, and null start/end dates. This corroborates active direct tenant-wide assignments with no scheduled expiry returned, rather than merely eligible or temporarily activated assignments. No role assignment was created or modified.

Detailed MFA diagnostic attempts and local recovery actions:

1. At 14:47:38 UTC, attempted read-only `GET https://graph.microsoft.com/beta/auditLogs/signIns/{eventId}` for the identified events, projecting only event metadata and authentication step method, time, success, requirement and result. The first request timed out at the configured 300-second HttpClient timeout. The terminal was cleaned up; no detailed event result was returned. Beta API documentation warns these APIs are subject to change.
2. At 14:52:55 UTC, a bounded collection retry stopped at the delegated-context guard because the prior session was no longer available. No query was executed.
3. At 14:53:10 UTC, restored the expected delegated administrator connection using `Connect-MgGraph -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -Scopes 'AuditLog.Read.All','RoleManagement.Read.Directory' -ContextScope Process -NoWelcome`. The subsequent query attempt failed locally because this installed Invoke-MgGraphRequest does not accept `-ClientTimeout`; no response was retrieved.
4. Inspected `Get-Command Set-MgRequestContext -Syntax` and `Get-MgRequestContext`. Original local settings were ClientTimeout 300 seconds and MaxRetry 3. At 14:53:34 UTC, set these to 60 seconds and zero retries, then attempted the beta sign-in collection filtered by the two user IDs and createdDateTime >= 13:00 UTC, with top=100 and a select list for event/authentication metadata. Graph returned HTTP 400 Unsupported Query, request ID `c794c669-466c-4b5d-a2a3-7818101e9599`. The first restoration used a mutable request-context reference and therefore retained 60 seconds/zero retries; the mismatch was observed, not treated as restored.
5. At 14:53:47 UTC, attempted separate per-user beta collection filters without select. The command failed with Invalid URI before returning event details. Its finally block explicitly restored `Set-MgRequestContext -ClientTimeout 300 -MaxRetry 3`, read the settings back and asserted both original values. Restoration succeeded. The cause of the URI failure was not established; no further diagnostic retries were made.

The successful v1.0 evidence and operator reports remain valid, but direct authentication-step verification is incomplete. Do not equate a reused MFA claim with a newly performed approval. No repeat manual sign-in was requested for this evidence gap. No passwords, tokens, IP addresses or locations were printed by these diagnostic projections. No tenant policy, account, authentication method or role writes occurred. Only local request settings were temporarily changed and restored, and this brief was edited. The assessor and generated report were untouched; the last assessment remains five implemented and five not configured.

### 29. Requested remaining-gap remediation: refreshed evidence, 2026-10-30 14:59-15:00 UTC

The operator requested remediation of the five gaps in the generated report. Read the formal lab requirements, assessor execution path and brief. Reran the unchanged assessor before any new remediation:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$true
```

The assessor found its prior Graph context unusable and reconnected successfully as the expected delegated administrator; Teams also connected to the expected tenant. It generated the 14:59:48 UTC report and snapshot `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-145948555Z.json`. Read the complete report and all ten snapshot entries. Results remain 5 IMPLEMENTED / 5 NOT-CONFIGURED / 0 UNKNOWN. The unresolved role-template coverage advisory remains; no assessor modification or result override was attempted.

At 15:00:14 UTC, guarded the expected delegated tenant/account, then queried Graph v1.0 `/me?$select=id,userPrincipalName`, `/users/fac73d10-5e8c-4f57-a92d-949f34e24f3d/licenseDetails`, and `/reports/authenticationMethods/userRegistrationDetails?$top=999`. Read all returned output; registration had no next page. Operator licenses remain POWERAPPS_DEV, Microsoft_Teams_Enterprise_New and VIRTUAL_AGENT_USL, with no Entra P1/P2 service plan. No license was assigned or purchased.

Registration now reports the operator, Isaiah and Nestor as MFA-registered/capable and SSPR-registered/capable. The operator has softwareOneTimePasscode; both recovery accounts have microsoftAuthenticatorPush and softwareOneTimePasscode. Seven accounts remain reported unregistered and incapable: AlexW, AllanD, DiegoS, JoniS, LynneR, MeganB and PattiF. MeganB is reported as an administrator. Registration may lag up to 36 hours; these data do not independently prove a fresh sign-in or reset test. The snapshot's latest SSPR count is now 3/10, superseding the earlier 1/10 count.

Queried Microsoft Learn for Conditional Access MFA, risk-policy prerequisites and emergency exclusions. Its sign-in-risk guidance states unregistered users cannot register MFA during risky sessions and can receive AADSTS53004. Accordingly, requesting licensing authorization and an explicit lab-impact decision before enforcement; the user's completed recovery tests are not being requested again. No Conditional Access policies or other tenant settings changed during these checks.

Recomputed assessor SHA256 with Get-FileHash: `6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D`, unchanged from baseline. Only this brief was manually edited; report and snapshot were generated solely by the assessor.

### 30. Disabled policy preparation, 2026-10-30 15:01-15:05 UTC

Asked for authorization to assign an available P2-containing license to the operator, a decision on enforcement impact for unregistered lab users and legacy clients, and confirmation of private recovery credential custody/rotation. Each answer stated the user was unavailable and requested autonomous work. This did not confirm the facts or override the earlier restriction on license assignments. No license purchase/assignment, credential change or policy activation was performed. Prepared disabled configurations only; these do not fulfill the lab's enforced-policy requirement.

Consulted Microsoft Learn Conditional Access creation examples and the complete risky-user remediation guidance. At 15:01:45 UTC, read and exhausted `GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies`; the inventory was empty. Connected with delegated `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess` using the expected tenant, Process context and NoWelcome. Verified the tenant, administrator account and Delegated authentication before writes. No application credentials or role-write permissions were used.

Constructed JSON bodies in the existing PowerShell session and submitted four `Invoke-MgGraphRequest -Method POST` calls to the v1.0 policy collection with `ContentType application/json`. No script files were created. Checked policy inventory before writes to prevent duplicates. Every body used state `disabled`, users.includeUsers `["All"]`, applications.includeApplications `["All"]`, and users.excludeUsers containing only Isaiah `3410ee51-2c02-4829-843a-e9f44757d8f3` and Nestor `e13ea4a7-a05a-4442-8864-0091a0e1244b`. No resource, group, role, location, platform or device exclusions/filters were introduced.

| Created UTC | Policy display name | Policy ID | Conditions and grants |
| --- | --- | --- | --- |
| 15:02:38 | Lab - Require MFA for all users | 7783a2d6-c798-46d1-8c2a-1dc5e8f36f16 | clientAppTypes all; sole builtInControls mfa. Submitted AND; Graph normalized this single grant to OR, which still makes MFA mandatory. No risk conditions or session controls. |
| 15:03:36 | Lab - Block legacy authentication | 7bbb668c-7ff1-4cb5-af86-71df370bf2ab | clientAppTypes exchangeActiveSync and other; sole builtInControls block, OR. No risk conditions or session controls. |
| 15:04:10 | Lab - Require MFA for medium and high sign-in risk | eef5c93e-1d05-49ea-9e65-4acbcc060f6d | clientAppTypes all; signInRiskLevels medium and high; sole builtInControls mfa, OR. |
| 15:04:28 | Lab - Require secure password change for high user risk | e2c761d0-06c5-47ac-b49c-8ffd87f2693f | clientAppTypes all; userRiskLevels high; builtInControls mfa and passwordChange, AND. No riskRemediation grant. |

Both risk drafts use sessionControls.signInFrequency with isEnabled true, frequencyInterval everyTime, authenticationType primaryAndSecondaryAuthentication. No optional alternative grant, authentication strength, custom authentication factor or terms-of-use grant was added. The passwordChange control is the formal lab's supported secure-password-change alternative; it does not reset any password while the policy is disabled.

Validation and resolved execution issues:

1. Immediately read each created policy by returned ID. The MFA assertion initially rejected Graph's single-grant OR normalization. Inspected the full response and corrected the assertion to accept AND or OR only when MFA is the sole grant and no alternative factor/terms/strength exists. Re-read and validated scope, exclusions, disabled state and mandatory MFA without another write.
2. The first immediate GET for the legacy draft returned 404 (request `0becb19c-5872-43ae-a57b-dae7514fd914`). Stopped the creation loop; a subsequent GET of the same ID succeeded and validated both client types, block grant, scope, exclusions and disabled state. No duplicate POST occurred.
3. The first immediate GET for the sign-in-risk draft returned 404 (request `cad86705-ea0e-4a61-8371-534dfdb3b41c`). Stopped again and re-read the same ID successfully. Verified thresholds, MFA, scope, exclusions, disabled state and both every-time authentication dimensions before creating the user-risk draft. These resolved 404s were consistent with propagation delay; no nonexistent-policy conclusion or duplicate write was made.
4. The longer final inventory assertion command was interrupted and produced no validation result. Repeated a shorter guarded, read-only collection GET and read the entire returned JSON. It contained exactly the four IDs above, no next page, all disabled, and the intended conditions and grants. Independently verified user risk high, MFA AND passwordChange and every-time primary-and-secondary authentication in this collection read, not just the POST response. No unintended narrowing condition or active policy was present.

No existing policy was patched or deleted. Rollback, if later authorized, is deletion of only these four draft IDs after checking their current state; no rollback was executed. No What If simulation, report-only observation, fresh enforced sign-in, legacy-client test or end-to-end secure password change was performed. Disabled draft validation is configuration evidence, not proof of enforcement safety or completed remediation.

### 31. Post-staging unchanged assessment, 2026-10-30 15:05:18 UTC

Reran the exact assessor command recorded in step 29 with no exclusion-approval override. The expected delegated Graph and Teams tenant/account were reported. Read the complete generated report and all ten entries in `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-150518351Z.json`.

Result: **5 IMPLEMENTED / 5 NOT-CONFIGURED / 0 UNKNOWN**. The snapshot recognizes the MFA and risk draft configurations but correctly reports them not enabled. The legacy block draft was independently read back; the assessor correctly finds no enabled legacy block. The role-template advisory persists. ExclusionsApproved is false because no approved-exclusion parameter was supplied; it was not overridden to improve coverage output. Before eventual enforcement, explicitly confirm the recovery exclusions and pass only the actually approved IDs to the unchanged assessor.

Only this brief was manually edited. The assessor and generated report were not manually modified. No account, role, license, authentication method, existing consent setting, Teams setting or SSPR setting was changed during draft preparation. Controls 1-5 remain incomplete pending owner decisions and applicable readiness checks; no finished lab is claimed.

### 32. Explicit owner approvals after the draft assessment

The owner answered "1. yes; 2. yes; 3. yes" to the three pending questions: assign an available existing P2-containing license to the working administrator without purchase or removal of existing licenses; confirm privately secured recovery credentials, replacement of exposed passwords and exclusion of Isaiah and Nestor from all four policies; accept legacy-authentication blocking and possible risk-related lockouts for the seven reported unregistered lab users. These approvals resolve the former authorization blocks. They do not prove enrollment, successful remediation or phishing-resistant recovery.

### 33. Approved operator license assignment, starting 2026-10-30 15:11:12 UTC

Guarded the expected delegated tenant and administrator and read Graph v1.0 `/subscribedSkus` and the operator's `id,userPrincipalName,usageLocation,assignedLicenses,assignedPlans`. The large inventory output was partially truncated; projected the retained structured response to identify the single available P2-containing candidate and re-read the operator's assignment prerequisites. `MICROSOFT_365_E7_NO_TEAMS`, SKU `38ff3437-c724-4f06-9b2f-05c09721cf7e`, was Enabled with 15 seats and 9 consumed, leaving 6 available. Existing usageLocation was US; no location change was necessary.

Consulted official Microsoft license-assignment examples. Connected to the same tenant using delegated `LicenseAssignment.ReadWrite.All`, `User.Read.All`, `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`, Process scope, NoWelcome; verified the exact tenant/account/authentication guard. No application credential or directory-role write was used.

Submitted one POST to `/users/fac73d10-5e8c-4f57-a92d-949f34e24f3d/assignLicense`, with addLicenses containing only that SKU, removeLicenses empty, and disabledPlans containing the 117 other plans from its inventory. Intended enabled user plans were AAD_PREMIUM (`41781fb2-bc02-4b7c-bd55-b576c07bb09d`), AAD_PREMIUM_P2 (`eec0eb4f-6444-4f95-aba0-50c24d67f998`) and MFA_PREMIUM (`8a256a2b-b617-496d-b51b-e76466e88db0`). No existing license was removed or reconfigured and no subscription was purchased.

Immediate GET validation rejected a disabled-plan count mismatch. A fresh GET of assignedLicenses/licenseAssignmentStates and `/licenseDetails` confirmed the new assignment Active/error None and all three intended plans provisioningStatus Success, but the same overly strict comparison failed again: Graph returned 106 disabled IDs instead of 117. No repeat assignment was submitted. A longer diagnostic command was interrupted without output; a shorter comparison of retained structured responses established that all eleven omitted IDs are Company-level plans. The only non-disabled User-level plans are the three intended plans. Corrected the validator to compare the exact user-level disabled-plan set; it passed, along with preservation of all three preexisting assignments and their disabled-plan lists and successful provisioning of all three required plans. The company-level omission was service normalization, not evidence that eleven unrelated user services were enabled. Existing licenses preserved: POWERAPPS_DEV, Microsoft_Teams_Enterprise_New and VIRTUAL_AGENT_USL.

Reviewed official Conditional Access What If evaluation documentation for the next policy scope check. No Conditional Access state has been changed at this point. Only this brief was manually edited; diagnostics checked after the edit. No rollback was executed.

### 34. Preflight and report-only staging, 2026-10-30 15:14 UTC

The first preflight command had an empty-pipe ParserError from piping directly after a foreach statement; parsing failed before any statement executed. Corrected only output formatting and reran. The guarded Graph v1.0 policy collection GET contained exactly the four approved IDs with no next page, all disabled. Compared displayName, conditions, grantControls and sessionControls to the previously validated full inventory using structured JSON equality; all matched, including the exact Isaiah/Nestor exclusion IDs. License verification remained successful.

For each of the four IDs in step 30, submitted a state-only PATCH to `/identity/conditionalAccess/policies/{id}` with `{"state":"enabledForReportingButNotEnforced"}`. Immediately GET-validated that state and unchanged displayName, conditions, grants and sessions before proceeding to the next policy. Verification times were 15:14:24 UTC (all-users MFA), 15:14:27 (legacy block), 15:14:29 (sign-in risk), and 15:14:32 (user risk). All passed. This temporary report-only staging was for simulation, not a prolonged observation period or enforcement claim.

### 35. Eight What If checks, completed 2026-10-30 15:15:39 UTC

Used the documented read-only simulation action `POST https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate`; no sign-in, user-risk state or credential was changed by these calls. Request context: `#microsoft.graph.userSignIn`, `#microsoft.graph.applicationContext`, SharePoint Online app ID `00000003-0000-0ff1-ce00-000000000000`, simulated Windows/US and appliedPoliciesOnly false. Default identity was the working administrator, browser client, sign-in/user risk none; individual tests varied only the stated inputs. No location, platform or device policy filters existed.

Read the normal-sign-in response and asserted the applicable policy IDs; each subsequent response returned exactly the same four IDs, with the expected applicable set. Results:

| Simulation | Applicable policies |
| --- | --- |
| Operator browser, no risk | All-users MFA only |
| Medium sign-in risk, no user risk | All-users MFA and sign-in-risk MFA |
| High sign-in risk, no user risk | All-users MFA and sign-in-risk MFA |
| High user risk, no sign-in risk | All-users MFA and secure password change |
| Exchange ActiveSync, no risk | All-users MFA and legacy block |
| Other legacy client, no risk | All-users MFA and legacy block |
| Isaiah, Other client, both risk levels high | None; all four analysisReasons = users |
| Nestor, Other client, both risk levels high | None; all four analysisReasons = users |

All eight assertions passed. These tests establish simulated applicability, including recovery exclusions, not successful MFA, password remediation or application service-dependency behavior. No additional recovery account test or password was requested.

### 36. Approved policy enforcement, 2026-10-30 15:15:57-15:16:05 UTC

Verified the exact delegated tenant/account plus successful licensing and simulation prerequisites. For each existing policy, freshly GET-read its report-only state and compared displayName, conditions, grants and session controls to the verified before-state. Submitted a state-only PATCH with `{"state":"enabled"}` to the same explicit ID, then immediately GET-validated enabled state and unchanged configuration before proceeding. All checks passed:

| Policy ID | Enabled readback UTC |
| --- | --- |
| 7783a2d6-c798-46d1-8c2a-1dc5e8f36f16 | 15:15:57 |
| 7bbb668c-7ff1-4cb5-af86-71df370bf2ab | 15:16:00 |
| eef5c93e-1d05-49ea-9e65-4acbcc060f6d | 15:16:02 |
| e2c761d0-06c5-47ac-b49c-8ffd87f2693f | 15:16:04 |

No policy was recreated, deleted or broadened. The only submitted policy changes were state transitions; service modification timestamps changed accordingly. Approved recovery exclusions, All users/All resources scope, both legacy types, risk thresholds, required grants and every-time authentication settings were preserved. Consent, Teams and SSPR were not rewritten.

Rollback, **not executed**: after an explicit operational decision, PATCH only the affected IDs above to state disabled, read back and reassess. This would restore the corresponding configuration gaps. Do not remove the operator's newly assigned P2 license while retaining policies that require it; any license rollback is a separate decision and must preserve the original three assignments. No forced sign-out, password reset or session revocation was performed.

### 37. Final unchanged assessment and integrity check, 2026-10-30 15:16 UTC

Executed:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$true -ApprovedExcludedUserId '3410ee51-2c02-4829-843a-e9f44757d8f3','e13ea4a7-a05a-4442-8864-0091a0e1244b'
```

The existing Graph/Teams connections identified the expected tenant and administrator; Graph was Delegated, Process scope. The assessor completed successfully at **15:16:36 UTC**, producing **10 IMPLEMENTED / 0 NOT-CONFIGURED / 0 UNKNOWN**. Read the complete generated report and every entry of `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-151636004Z.json`; all ten entries identify the expected tenant/time.

Controls 1, 2, 4 and 5 now report CoverageVerified true, Resolved true, empty MissingAdministrativeRoles and ExclusionsApproved true. The earlier role-template warning was not emitted in this run; no role metadata was modified, and this is not a claim to have repaired its earlier underlying cause. The enabled all-users policy provides broad configuration coverage. Legacy blocking and the prior consent/Teams settings are IMPLEMENTED. SSPR confirmation was explicitly true based on the earlier independent portal/audit evidence, despite the snapshot's generic wording about the script default.

Registration caveats remain: one of four checked administrative accounts is not reported MFA-capable; seven of ten enabled accounts are not MFA-capable; three of ten members are SSPR-registered/capable and seven are not. No registration data were missing. Reports may lag up to 36 hours. Owner acceptance of lab impact is not enrollment or reset-readiness evidence.

At 15:16:48 UTC, Get-FileHash verified the assessor SHA256 still exactly matches baseline: `6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D`. Only this brief was manually edited and checked with document diagnostics. The report/snapshot were generated solely by the unchanged assessor; no manual score edits, new script files, accounts, roles, credentials, purchases, commits or branches were made. Lab configuration requirements are complete; operational follow-up below is explicitly outside the claimed verification.

### 38. Requested assessor rerun, 2026-10-30 15:22:01 UTC

At the user's request, ran the unchanged assessor once more with the exact command in step 37, including assessment-only Graph scope selection, Teams user authentication, independently supported SSPR confirmation and both approved recovery exclusion IDs. Graph reported the expected delegated administrator and tenant in Process scope. Required modules were already present.

Teams connected to the expected tenant, but its Global meeting-policy read failed with `Forbidden / Access Denied` and the message "Provide different credential or request access." The assessor continued and generated **7 IMPLEMENTED / 0 NOT-CONFIGURED / 3 UNKNOWN**. Controls 7, 8 and 9 are UNKNOWN because their shared Teams read failed. Controls 1-6 and 10 remain IMPLEMENTED; the MFA/risk configuration coverage and approved-exclusion evidence remain verified. Registration counts are unchanged. The error alone does not identify its underlying cause or demonstrate that any Teams setting changed.

Read the complete generated report and all ten entries of `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-152201805Z.json`, confirming the expected tenant and timestamp. Updated this brief's current status and table while preserving the earlier successful assessment as historical evidence; document diagnostics checked afterward. No tenant remediation, role/license assignment, policy change, session reset or additional assessment retry was performed. The assessor was not edited and its report/snapshot were generated only by the script. Teams authorization remains unresolved; a fresh delegated Teams sign-in and read-access check are the next diagnostic steps, not automatic justification for another role assignment or weakening Conditional Access.

### 39. Requested unchanged rerun, 2026-10-30 15:26:24 UTC

The user explicitly reiterated that the report must only be generated by the assessor. Executed the unchanged command in step 37 exactly once, retaining the same authentication, SSPR confirmation and approved exclusions. The expected delegated Graph administrator/tenant were reported. Teams again connected to the expected tenant but returned Forbidden/Access Denied for the Global meeting-policy read. The script completed with **7 IMPLEMENTED / 0 NOT-CONFIGURED / 3 UNKNOWN**, with only controls 7-9 unknown.

Read the complete newly generated report. It identifies snapshot `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-152624696Z.json`. Neither the report nor the assessor was manually edited; only this brief was updated to record the action. No tenant settings, roles, licenses or authentication sessions were changed to address the unresolved Teams read failure.

### 40. Teams access diagnostics after user-reported reconnect, 2026-10-30 15:36-15:41 UTC

The user reported completing interactive Teams reconnection and authorized direct read testing, existing-role/PIM checks, sign-in/Conditional Access diagnosis and an unchanged assessment only after Teams read access succeeds. Two direct `Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop` checks returned Access Denied. Between them, `Connect-MicrosoftTeams` with the explicit expected TenantId and AccountId returned the expected operator and tenant. No policy setter was run.

Guarded the existing Graph context against the expected tenant, operator and Delegated authentication. A v1.0 roleAssignments GET filtered to operator object ID `fac73d10-5e8c-4f57-a92d-949f34e24f3d`, expanding roleDefinition, returned active Global Administrator at directory scope `/`, template `62e90394-69f5-4237-9190-012177145e10`, with no additional page. No PIM activation or new role assignment was needed or performed.

At 15:38:13 UTC, retrieved the operator's v1.0 sign-ins since 15:15 UTC, following pagination. The returned MS Teams Powershell Cmdlets event at 15:26:18 UTC (`5aa49340-1018-423e-8a7a-0ae3e08e6600`) targeted Microsoft Graph, returned errorCode 0 and Conditional Access success. All-users MFA succeeded; the legacy-block and two risk policies were not applied. Other returned events also had errorCode 0. This does not establish successful authorization against the Teams policy service or rule out failures in non-interactive requests or events not yet available.

Consulted Microsoft Learn connection and sign-in API documentation. Two supplemental read-only beta requests for nonInteractiveUser events, scoped to the same operator and 15:15-15:41 UTC, failed with `Invalid URI: The format of the URI could not be determined`; no non-interactive log results were obtained. The first cleanup attempted to pass a TimeSpan where ClientTimeout requires integer seconds; explicitly restored ClientTimeout 300 seconds and MaxRetry 3. The second attempt used a literal encoded URI and restored those settings in finally. No additional Graph scopes were requested. Beta was limited to the documented non-interactive diagnostic gap, not the assessor.

Opened Teams admin center and read Global (Org-wide default) without changing controls or saving. A stale-element click timed out, then succeeded after refreshing the page snapshot. The loaded portal displayed Who can bypass the lobby = People who were invited; Who can present = Only organizers and co-organizers; Anonymous users can join a meeting unverified = Off. The separate Anonymous users can join a meeting after verifying setting displayed By email code. These observations do not replace the assessor's failed PowerShell read or establish a blanket ban on verified external participation. No meeting needs scheduling for this access diagnosis; live meeting behavior remains untested.

Get-FileHash again matched the baseline assessor SHA256 exactly. The assessor was not rerun because direct read access remains denied; the latest report remains the 15:26:24 UTC 7/0/3 result. No assessor/report edits, tenant policy changes, role grants, PIM activations or license changes were made. Only this brief was manually edited to record the diagnostics.

### 41. Fresh non-WAM Teams session diagnostic, 2026-10-30

After step 40, executed `Disconnect-MicrosoftTeams -ErrorAction Stop`, then `Connect-MicrosoftTeams -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -AccountId 'admin@wwlcpx73950877.onmicrosoft.com' -DisableWAM -ErrorAction Stop`. The supported browser-based connection returned the expected operator and tenant. A subsequent direct Global meeting-policy read again returned Access Denied. Changing the local authentication path did not resolve the failure; no claim is made that WAM caused it.

The fresh Teams session remains connected. No credentials or tokens were handled by the assistant, no tenant configuration or role was changed, and no assessment was run because the requested prerequisite read still fails. Investigating the remaining Teams PowerShell/service authorization failure requires additional service-specific evidence, such as non-interactive sign-in details or Microsoft support diagnostics; current evidence does not justify adding roles or weakening Conditional Access. Scheduling a meeting is unnecessary for this diagnosis. The report remains unchanged at 7 IMPLEMENTED / 0 NOT-CONFIGURED / 3 UNKNOWN.

### 42. Read-only Teams command comparison, 2026-10-30 15:53 UTC

Following the supplied resolution guide, verified the expected delegated Graph context and compared three read-only Teams commands in the existing connected session. PowerShell was 7.6.6 Core; the loaded MicrosoftTeams module was 8.0.0 from `C:\Users\Admin\Documents\PowerShell\Modules\MicrosoftTeams\8.0.0\MicrosoftTeams.psm1`.

- At 15:53:00.6539890 UTC, `Get-Team -NumberOfThreads 1 -ErrorAction Stop` succeeded and returned one object; team contents were not printed.
- At 15:53:03.6071944 UTC, `Get-CsTenant -ErrorAction Stop` failed with Access Denied, error ID `Forbidden,Microsoft.Teams.ConfigApi.Cmdlets.GetCsTenant`, and a ConfigAPI generated runtime RestException.
- At 15:53:04.4783008 UTC, `Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop` failed with code Forbidden and Access Denied, error ID `Forbidden,Microsoft.Teams.Policy.Administration.Cmdlets.Core.GetTeamsMeetingPolicyCmdlet`, and exception type `Microsoft.Teams.Policy.Administration.Cmdlets.Providers.PolicyRpException`.

Selected error metadata did not expose an HTTP status value or correlation ID. The comparison narrows the observed failure to Teams administrative configuration operations rather than the entire Teams connection; it does not establish whether the cause is local, token/resource-specific, Conditional Access, or tenant-side authorization. No module update, diagnostic file creation, tenant setting change or assessor rerun was performed. The existing 7/0/3 report remains unchanged.

### 43. Non-interactive sign-in log investigation, 2026-10-30

At the user's request to check the logs, reused the existing delegated Graph session and verified the expected tenant, operator and Delegated authentication. Consulted Microsoft's sign-in API and Conditional Access guidance. A further read-only beta sign-in query was intended to cover the operator's interactiveUser and nonInteractiveUser events from 15:15 to 16:00 UTC. The first request, for interactiveUser, failed locally inside Invoke-MgGraphRequest with `Invalid URI: The format of the URI could not be determined`, despite explicit absolute HTTPS URI validation. No new API records were returned and the nonInteractiveUser request was not reached. Restored the saved timeout/retry settings in finally; a subsequent Get-MgRequestContext independently confirmed ClientTimeout 00:05:00 and MaxRetry 3. No new consent was requested.

Used the signed-in Entra admin center instead; its account header confirmed the expected operator and tenant. Applied Username contains `admin@wwlcpx73950877.onmicrosoft.com` and UTC display. An attempted custom interval could not be applied because the date picker reset time values and retained a validation error. Restored Last 24 hours and opened User sign-ins (non-interactive), with Time aggregate 24 hours; the custom 15:15-16:00 UTC filter was not applied. Correlated individual expanded-event UTC timestamps rather than treating the aggregate midnight timestamp as an event time. Several pointer selectors/stability checks timed out; keyboard activation opened the event rows and tabs. The detail view retained its previous tab when changing events, so Basic info was explicitly selected for the second event.

The loaded non-interactive grid contained a group of 10 Interrupted sign-ins, Conditional Access Failure, for application Skype and Teams Tenant Admin API requesting Microsoft Graph. Eight expanded event rows were read, at 15:22:01, 15:26:24, 15:36:14, 15:37:43, 15:38:41, 15:41:57, 15:53:04 and 15:53:05 UTC. The first two align with the failed assessor reruns; the last two align with the direct command comparison in step 42. This was a targeted review of loaded records, not an exhaustive export or pagination of all sign-ins or all ten group members.

Opened the two latest events and inspected Basic info, Authentication Details and Conditional Access:

| UTC time | Request ID | Correlation ID |
| --- | --- | --- |
| 2026-10-30 15:53:04 | `8ab0581a-d793-4b2d-8375-73551e3c8200` | `bbd76e63-5b05-4bd5-89a0-726a3d341ed0` |
| 2026-10-30 15:53:05 | `6b24e3a0-d07a-4265-9efd-78e685bc1c00` | `fe4de060-a5c0-4fad-bc1b-f93d7dbdffcb` |

Both events reported Status Interrupted, authentication requirement Multifactor authentication, and Additional Details beginning `User needs to perform multi-factor authentication.` Authentication Details showed Succeeded false and `MFA required in Azure AD`, with Conditional Access as the applied authentication policy source. In each event, `Lab - Require MFA for all users` had grant control Require multifactor authentication and result Failure. `Lab - Block legacy authentication`, `Lab - Require MFA for medium and high sign-in risk`, and `Lab - Require secure password change for high user risk` were Not Applied. The inspected portal fields did not expose a numeric AADSTS error code; none is inferred from documentation examples.

The 15:53:05 Basic info panel explicitly identified application Skype and Teams Tenant Admin API, application ID `48ac35b8-9aa8-4d74-927d-1f4a14a0b239`, requesting resource Microsoft Graph, resource ID `00000003-0000-0000-c000-000000000000`, in the expected resource tenant. Client app was Browser and client credential type was Client assertion. Here the Teams administrative API is the client of a downstream Graph request, not the target resource. This is distinct from the earlier successful MS Teams Powershell Cmdlets-to-Graph interactive event in step 40. Other loaded non-interactive groups showed successful requests, including Teams PowerShell to Graph and the Teams admin portal to the Teams administrative API; those aggregates do not negate these specific interrupted requests.

The logs now establish a downstream MFA/Conditional Access interruption closely time-correlated with the Teams administrative read failures. The earlier successful interactive sign-in did not rule this out. Microsoft documents how downstream API requests can require a separate Conditional Access claims challenge: [Developer guidance for Microsoft Entra Conditional Access](https://learn.microsoft.com/entra/identity-platform/v2-conditional-access-dev-guide#scenario-app-performing-the-on-behalf-of-flow). The evidence is consistent with that class of failure, but does not prove the exact token flow, cache condition, or client/service challenge-handling defect. No command-side correlation ID was captured in step 42, so the command-to-event linkage is temporal and account/application-based, not an end-to-end trace match. It does not justify additional roles or disabling the MFA policy.

No tenant configuration, roles, licenses, credentials or modules were changed. No secrets were requested or token contents inspected. No assessment was rerun, no generated report was manually changed, and no commit or push was performed. Only this brief was manually updated. The latest generated assessment remains 7 IMPLEMENTED / 0 NOT-CONFIGURED / 3 UNKNOWN. Preserve security enforcement while investigating supported MFA-capable Teams authentication/challenge handling; the event IDs above are available for Microsoft support if needed. A successful direct Global policy read remains the prerequisite for rerunning the unchanged assessor.

### 44. API and module constraint clarification, 2026-10-30

Following the user's reminder of the best-practices requirements, checked the assessor's imports and current Microsoft Learn documentation. The assessor imports Microsoft.Graph.Authentication and MicrosoftTeams. Its Get-CsTeamsMeetingPolicy call is documented in the supported [MicrosoftTeams module](https://learn.microsoft.com/powershell/module/microsoftteams/get-csteamsmeetingpolicy?view=teams-ps); the Cs prefix and the Skype and Teams Tenant Admin API service name do not imply use of the retired Skype for Business Online PowerShell module. No deprecated module was used for the recorded Teams diagnostics.

The beta requests in steps 40 and 43 were isolated, read-only diagnostic attempts outside the unchanged assessor and returned no records. Microsoft's [activity-log guidance](https://learn.microsoft.com/entra/identity/monitoring-health/howto-analyze-activity-logs-with-microsoft-graph#access-reports-using-microsoft-graph-explorer) documents beta for non-interactive sign-in queries. However, that diagnostic gap is not itself a required tenant setting under the user's narrowly stated beta exception. The combined retry also attempted interactiveUser through beta despite the available v1.0 interface; that was unnecessary and did not follow the GA-first requirement. The successful diagnostic evidence came from the Entra portal, not those beta requests. Use supported Graph v1.0 operations and the portal for this investigation; do not make further beta diagnostic requests without an explicitly approved exception. No beta dependency was added to the assessor, and no assessor, report, tenant setting or module was changed following this clarification.

### 45. Supported authentication remediation investigation, 2026-10-30

At the user's request to fetch online documentation and continue fixing Teams access, fetched Microsoft's [Connect-MicrosoftTeams reference](https://learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams?view=teams-ps), [release notes](https://learn.microsoft.com/microsoftteams/teams-powershell-release-notes), and [supported versions](https://learn.microsoft.com/microsoftteams/teams-powershell-supported-versions). Also consulted Microsoft Learn search and code samples. The reference documents UseDeviceAuthentication as device-code authentication instead of a browser control, and interactive authentication for MFA-enabled accounts. The fetched release notes list installed version 8.0.0 as the latest GA release; the newer 8.0.1-preview entry describes an unrelated call-queue change. No module installation or update was performed. Credential/ROPC and manually acquired token examples were not used.

Verified the existing delegated Graph context matches the expected operator and tenant. Local command metadata confirmed MicrosoftTeams 8.0.0 is loaded and Connect-MicrosoftTeams supports UseDeviceAuthentication. The next bounded test is a fresh delegated device-code sign-in followed by Get-CsTeamsMeetingPolicy -Identity Global. This tests whether a different supported sign-in flow satisfies the downstream MFA requirement; documentation does not guarantee it will resolve this failure. At this checkpoint, that sign-in has not yet been started and access is not restored. The assessor, generated report, roles and Conditional Access policies remain unchanged; no beta request, consent expansion, commit or push was performed.

### 46. Device-code authentication and restored Teams read access, 2026-10-30

The initial multiline prerequisite command returned only its first assignment, and terminal-last-command returned no active command. Repeated the bounded read-only check in a single script block; it confirmed the expected delegated Graph identity, loaded Teams version and device-authentication parameter described in step 45. No authentication data was inspected.

After checking the expected Graph context, disconnected only the local MicrosoftTeams session and started this supported delegated connection at **16:20:54.0259881 UTC**:

```powershell
Disconnect-MicrosoftTeams -ErrorAction Stop
Connect-MicrosoftTeams -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -AccountId 'admin@wwlcpx73950877.onmicrosoft.com' -UseDeviceAuthentication -ErrorAction Stop
```

The command issued Microsoft's device sign-in prompt and completed successfully with the expected account and tenant. The assistant did not enter credentials or inspect tokens; device codes are not copied into this brief. Authentication-step telemetry for this new connection was not independently inspected.

The first local identity guard rejected the connection object before any policy call because Account is an AzureAccount object, not a string. Inspected only result type, account/tenant text and their types; TenantId is a Guid. Corrected the local guard to compare their string representations. At **16:25:35.4505713 UTC**, Get-CsTeamsMeetingPolicy -Identity Global -ErrorAction Stop succeeded and returned exactly one Global policy with AutoAdmittedUsers InvitedUsers, DesignatedPresenterRoleMode OrganizerOnlyUserOverride, and AllowAnonymousUsersToJoinMeeting False. No meeting-policy write was needed.

This establishes restored access following a different supported authentication flow, consistent with the earlier downstream MFA failures. It does not prove the precise prior token/cache or service challenge-handling defect, nor guarantee future session behavior. No MFA policy was disabled, no exclusion or role was added, no PIM activation was performed, and no module was updated. No beta diagnostics or manual token acquisition were used.

### 47. Unchanged reassessment after access restoration, 2026-10-30 16:26:09 UTC

Required the successful direct Teams read and checked the assessor SHA256 against the baseline; it matched `6A9431E2D3C7694F49D4EBAEE43D0FA224BA36254BAE7C641EA6ACAAB2A9A87D`. Executed:

```powershell
.\scripts\assess.ps1 -TenantId '7a9b5e57-db07-4525-896c-0341e35c8f28' -ConsentForAllScripts:$false -UseTeamsUserAuthentication -SsprAllScopeConfirmed:$true -ApprovedExcludedUserId '3410ee51-2c02-4829-843a-e9f44757d8f3','e13ea4a7-a05a-4442-8864-0091a0e1244b'
```

The assessor reported the existing Graph context was no longer usable and reconnected using its existing authentication logic. Output confirmed the expected delegated Graph operator/tenant and the expected Teams identity. The script completed with **10 IMPLEMENTED / 0 NOT-CONFIGURED / 0 UNKNOWN** and regenerated the report itself. Read the complete generated report, including all ten results and its footer. Snapshot path: `C:\SecureM365Snapshots\7a9b5e57-db07-4525-896c-0341e35c8f28-m365-recommendation-status-20261030-162609133Z.json`; this new snapshot was not independently read. The report retains its configuration-coverage and registration-lag caveats.

Updated this brief's current status and control table, preserving the earlier failure records. Only this brief was manually edited; the assessor was not modified and the report was not manually altered. No tenant remediation writes, commit or push were performed during this restoration and reassessment.

## Operational Follow-up

1. Recovery selection, prior user-confirmed tests, credential custody and exact exclusions are approved. Available sign-in/role/registration evidence corroborates the tests, but fresh authentication-step evidence and an independently observed administrative recovery operation remain unavailable. Do not request repeat tests solely because detailed telemetry was unavailable.
2. Operator P1/P2 licensing, eight scope simulations, policy activation/readback and the final unchanged assessment are complete. Final configuration coverage is verified with the approved recovery exclusions; the earlier role-template warning was not emitted. Maintain appropriate licensing and review coverage as membership and policies change.
3. The owner explicitly accepted lab enforcement before registration completion. Complete registration and an authorized non-administrator self-reset test before relying operationally on high-user-risk remediation. The seven reported unregistered users may be blocked during risky sign-ins and need administrator-assisted recovery. Do not reset the working administrator password as a test.
4. Live legacy-client and Teams meeting behavior remain untested. A fresh device-code connection and administrative read succeeded in step 46, but its authentication-step telemetry was not independently reviewed. Follow-up testing does not authorize unrelated configuration changes.
5. Teams read access is restored and all ten controls are verified by the latest unchanged assessor. If denial recurs, correlate fresh sign-in evidence and use supported interactive authentication without weakening Conditional Access or adding roles.

Configuration checks and lab scores do not establish complete operational security coverage. Do not provide passwords, QR secrets or tokens.

## References

- [Assign licenses](https://learn.microsoft.com/microsoft-365/enterprise/assign-licenses-to-user-accounts-with-microsoft-365-powershell?view=o365-worldwide): addLicenses, disabledPlans and preservation through empty removeLicenses.
- [Conditional Access What If API](https://learn.microsoft.com/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0): simulated policy applicability; not a live sign-in or service-dependency test.
- [Configure user consent](https://learn.microsoft.com/entra/identity/enterprise-apps/configure-user-consent): delegated authorization permission, nested PATCH and preservation of owned-resource assignments; existing grants unaffected.
- [Set-CsTeamsMeetingPolicy](https://learn.microsoft.com/powershell/module/microsoftteams/set-csteamsmeetingpolicy?view=teams-ps): supported property values and behavior.
- [Enable SSPR](https://learn.microsoft.com/entra/identity/authentication/tutorial-enable-sspr): supported portal scope/Save workflow and registration prerequisites.
- [SSPR licensing](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-licensing): licenses required for intended beneficiaries; P1/P2 provide reset features. No blanket administrator licensing exemption is asserted here.
- [Administrator reset policy differences](https://learn.microsoft.com/entra/identity/authentication/concept-sspr-policy#administrator-reset-policy-differences): separate default administrator SSPR policy and possible trial/domain exceptions, not proof of reset readiness.
- [Emergency access accounts](https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access): recovery-account planning and independent testing.
- [Register passkeys in Authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-register-passkey-authenticator): supported phone registration, MFA bootstrap and device prerequisites.
- [Enable passkeys in Authenticator](https://learn.microsoft.com/entra/identity/authentication/how-to-enable-authenticator-passkey): policy profiles, Authenticator providers and cross-device requirements.
- [List FIDO2 authentication methods](https://learn.microsoft.com/graph/api/fido2authenticationmethod-list?view=graph-rest-1.0): direct passkey enumeration and delegated read permissions.
