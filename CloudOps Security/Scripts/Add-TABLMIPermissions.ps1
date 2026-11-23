param (
    [Parameter(Mandatory = $true)]
    [guid] $TenantId,

    [Parameter(Mandatory = $true)]
    [string] $ManagedIdentityObjectId,

    # Exchange Online role group that grants the managed identity the Tenant AllowBlockList
    # Manager role and nothing else. This is the least-privilege alternative to assigning the
    # identity the Security Administrator or Exchange Administrator directory role.
    [string] $RoleGroupName = "CloudOps Security Tenant Allow Block List"
)

$tenantAllowBlockListRole = "Tenant AllowBlockList Manager"

# The cmdlets the function app runs. The role must contain all of them, otherwise
# Connect-ExchangeOnline -CommandName loads a session without them.
$requiredCmdlets = @(
    "Get-TenantAllowBlockListItems",
    "New-TenantAllowBlockListItems",
    "Remove-TenantAllowBlockListItems"
)

function Add-RequiredModules {

    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications",
        "ExchangeOnlineManagement"
    )

    foreach ($module in $modules) {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Verbose -Message "Did not find module `"$module`", attempting to install."
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
            }
            catch {
                throw "Failed to install module `"$module`". Error: $($_.Exception.Message)"
            }
        }

        Write-Verbose -Message "Attempting to import module `"$module`""
        try {
            Import-Module -Name $module -ErrorAction Stop
        }
        catch {
            throw "Failed to import module `"$module`". Error: $($_.Exception.Message)"
        }
    }
}

function Confirm-ContextScopes {
    Param(
        [Parameter(Mandatory = $true)]
        [array] $Scopes
    )

    $scopeErrors = @()

    try {
        $context = Get-MgContext -ErrorAction Stop
    }
    catch {
        throw "Failed to get Microsoft Graph context. Make sure that you are connected to Microsoft Graph: `"Connect-MgGraph`""
    }

    foreach ($scope in $Scopes) {
        $hasScope = $false

        if ($scope -in $context.Scopes) {
            $hasScope = $true
        }

        if (-not $hasScope) {
            $scopeErrors += "Necessary scopes not found in current Microsoft Graph context. You need the following scopes: $Scopes"
        }
    }

    return $scopeErrors | Select-Object -Unique
}

function Add-ExchangeManageAsAppPermission {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $ManagedIdentityObjectId
    )

    $ExoApp = Get-MgServicePrincipal -Filter "AppId eq '00000002-0000-0ff1-ce00-000000000000'"
    $AppPermission = $ExoApp.AppRoles | Where-Object { $_.Value -eq "Exchange.ManageAsApp" }

    # Checked first so that the script can be re-run against an identity that already has the
    # permission, for example to add the role group to an existing deployment.
    $existingAssignment = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -All |
        Where-Object { $_.ResourceId -eq $ExoApp.Id -and $_.AppRoleId -eq $AppPermission.Id }

    if ($existingAssignment) {
        Write-Host "Managed identity already has Exchange.ManageAsApp."
        return
    }

    $AppRoleAssignment = @{
        "PrincipalId" = $ManagedIdentityObjectId
        "ResourceId"  = $ExoApp.Id
        "AppRoleId"   = $AppPermission.Id
    }

    $null = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ManagedIdentityObjectId -BodyParameter $AppRoleAssignment -ErrorAction Stop
    Write-Host "Assigned Exchange.ManageAsApp to the managed identity."
}

function Add-TenantAllowBlockListRoleGroup {
    Param(
        [Parameter(Mandatory = $true)]
        $ManagedIdentity,

        [Parameter(Mandatory = $true)]
        [string] $RoleGroupName
    )

    try {
        $null = Get-ManagementRole -Identity $tenantAllowBlockListRole -ErrorAction Stop
    }
    catch {
        throw "Management role `"$tenantAllowBlockListRole`" was not found in Exchange Online. Error: $($_.Exception.Message)"
    }

    $roleCmdlets = (Get-ManagementRoleEntry -Identity "$tenantAllowBlockListRole\*").Name
    $missingCmdlets = $requiredCmdlets | Where-Object { $_ -notin $roleCmdlets }
    if ($missingCmdlets) {
        throw "Management role `"$tenantAllowBlockListRole`" does not contain the cmdlets the function app needs: $($missingCmdlets -join ', ')"
    }

    # Exchange keeps its own pointer to the Entra service principal. Role group membership is
    # granted to that pointer, so it has to exist before the identity can be added.
    $exoServicePrincipal = Get-ServicePrincipal -Identity $ManagedIdentity.Id -ErrorAction SilentlyContinue
    if (-not $exoServicePrincipal) {
        $exoServicePrincipal = New-ServicePrincipal -AppId $ManagedIdentity.AppId -ObjectId $ManagedIdentity.Id -DisplayName $ManagedIdentity.DisplayName -ErrorAction Stop
        Write-Host "Created Exchange Online service principal for `"$($ManagedIdentity.DisplayName)`"."
    }
    else {
        Write-Host "Exchange Online service principal for `"$($ManagedIdentity.DisplayName)`" already exists."
    }

    $roleGroup = Get-RoleGroup -Identity $RoleGroupName -ErrorAction SilentlyContinue
    if (-not $roleGroup) {
        $roleGroup = New-RoleGroup -Name $RoleGroupName -Roles $tenantAllowBlockListRole -Description "Lets the CloudOps Security tenant allow/block list function app manage Tenant Allow/Block List entries." -ErrorAction Stop
        Write-Host "Created role group `"$RoleGroupName`" with role `"$tenantAllowBlockListRole`"."
    }
    else {
        $roleAssignment = Get-ManagementRoleAssignment -Role $tenantAllowBlockListRole -RoleAssignee $RoleGroupName -Delegating $false -ErrorAction SilentlyContinue
        if (-not $roleAssignment) {
            $null = New-ManagementRoleAssignment -Role $tenantAllowBlockListRole -SecurityGroup $RoleGroupName -ErrorAction Stop
            Write-Host "Assigned role `"$tenantAllowBlockListRole`" to existing role group `"$RoleGroupName`"."
        }
        else {
            Write-Host "Role group `"$RoleGroupName`" already has role `"$tenantAllowBlockListRole`"."
        }
    }

    try {
        Add-RoleGroupMember -Identity $RoleGroupName -Member $exoServicePrincipal.Identity -ErrorAction Stop
        Write-Host "Added `"$($ManagedIdentity.DisplayName)`" to role group `"$RoleGroupName`"."
    }
    catch {
        if ($_.Exception.Message -notmatch "already a member") {
            throw "Failed to add `"$($ManagedIdentity.DisplayName)`" to role group `"$RoleGroupName`". Error: $($_.Exception.Message)"
        }
        Write-Host "`"$($ManagedIdentity.DisplayName)`" is already a member of role group `"$RoleGroupName`"."
    }
}

# Directory roles assigned directly to the managed identity. Earlier setups gave it Security
# Administrator or Exchange Administrator, which the role group replaces, so they are listed
# for the admin to remove. Roles reached through a role-assignable group aren't listed.
function Get-DirectoryRoleNames {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $ManagedIdentityObjectId
    )

    $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$ManagedIdentityObjectId'&`$expand=roleDefinition"
    $assignments = (Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop).value

    return @($assignments | ForEach-Object { $_.roleDefinition.displayName } | Sort-Object -Unique)
}

$scopes = @(
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.Read.Directory"
)

Add-RequiredModules

$null = Connect-MgGraph -Scopes $scopes -TenantId $TenantId

$scopeErrors = Confirm-ContextScopes -Scopes $scopes
if (-not $null -eq $scopeErrors) {
    throw $scopeErrors
}

$managedIdentity = Get-MgServicePrincipal -ServicePrincipalId $ManagedIdentityObjectId -ErrorAction Stop

Add-ExchangeManageAsAppPermission -ManagedIdentityObjectId $ManagedIdentityObjectId

Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop

try {
    # Connect-ExchangeOnline signs in to whichever tenant the chosen account belongs to, which
    # need not be the one Graph was connected to above.
    $exoTenantId = (Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' } | Select-Object -First 1).TenantID
    if (-not $exoTenantId -or [guid]"$exoTenantId" -ne $TenantId) {
        throw "Exchange Online session is connected to tenant [$exoTenantId], expected [$TenantId]. Sign in with an account from the expected tenant."
    }

    Add-TenantAllowBlockListRoleGroup -ManagedIdentity $managedIdentity -RoleGroupName $RoleGroupName
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false
}

Write-Host "Done. Exchange Online can take up to two hours to apply role group changes to the managed identity."

$directoryRoles = Get-DirectoryRoleNames -ManagedIdentityObjectId $ManagedIdentityObjectId
if ($directoryRoles) {
    Write-Warning ("The managed identity is also assigned these Microsoft Entra roles: {0}. The function app needs only the role group this script configured, so these roles can be removed from the managed identity unless something else depends on them." -f ($directoryRoles -join ', '))
}
