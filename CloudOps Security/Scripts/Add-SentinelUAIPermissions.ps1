param (
    [Parameter(Mandatory = $true)]
    [guid] $TenantId,

    [Parameter(Mandatory = $false)]
    [string] $UAIDisplayName = 'uai-sentinel'
)

function Add-RequiredModules {

    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
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

    try {
        $context = Get-MgContext -ErrorAction Stop
    }
    catch {
        throw "Failed to get Microsoft Graph context. Make sure that you are connected to Microsoft Graph: `"Connect-MgGraph`""
    }

    $scopeErrors = foreach ($scope in $Scopes) {
        if ($scope -notin $context.Scopes) {
            "Necessary scopes not found in current Microsoft Graph context. You need the following scopes: $Scopes"
        }
    }

    return $scopeErrors | Select-Object -Unique
}

function Invoke-PermissionChange {
    Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('add', 'remove')]
        [string] $Action,

        [Parameter(Mandatory = $true)]
        [string] $ResourceName,

        [Parameter(Mandatory = $true)]
        [string] $PermissionValue,

        [Parameter(Mandatory = $true)]
        [scriptblock] $Operation
    )

    $preposition = if ($Action -eq 'add') { 'to' } else { 'from' }

    try {
        Write-Host "Attempting to $Action $ResourceName permission `"$PermissionValue`" $preposition UAI." -ForegroundColor Cyan -NoNewline
        $null = & $Operation
        Write-Host " - Success!" -ForegroundColor Green
    }
    catch {
        Write-Host " - Failed!" -ForegroundColor Red
        Write-Warning -Message "Failed to $Action $ResourceName permission `"$PermissionValue`" $preposition UAI. Error: $($_.Exception.Message)"
    }
}

function Sync-UAIPermissions {
    Param(
        [Parameter(Mandatory = $true)]
        [string] $ResourceName,

        [Parameter(Mandatory = $true)]
        [string] $AppId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array] $Permissions,

        [Parameter(Mandatory = $true)]
        [string] $UAIServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array] $UAIAssignments
    )

    $resourceSPN = Get-MgServicePrincipal -Filter "appId eq '$AppId'"
    $desiredRoles = $resourceSPN.AppRoles | Where-Object { $_.Value -in $Permissions }
    $currentAssignments = $UAIAssignments | Where-Object { $_.ResourceId -eq $resourceSPN.Id }

    # Add the permissions that are missing
    foreach ($role in $desiredRoles) {
        if ($role.Id -in $currentAssignments.AppRoleId) {
            Write-Host "$ResourceName permission `"$($role.Value)`" is already assigned to UAI." -ForegroundColor Green
            continue
        }

        $body = @{
            principalId = $UAIServicePrincipalId
            resourceId  = $resourceSPN.Id
            appRoleId   = $role.Id
        }

        Invoke-PermissionChange -Action 'add' -ResourceName $ResourceName -PermissionValue $role.Value -Operation {
            New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $resourceSPN.Id -BodyParameter $body -ErrorAction Stop
        }
    }

    # Remove the permissions that are no longer wanted
    foreach ($assignment in ($currentAssignments | Where-Object { $_.AppRoleId -notin $desiredRoles.Id })) {
        $permissionValue = ($resourceSPN.AppRoles | Where-Object { $_.Id -eq $assignment.AppRoleId }).Value

        Invoke-PermissionChange -Action 'remove' -ResourceName $ResourceName -PermissionValue $permissionValue -Operation {
            Remove-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $resourceSPN.Id -AppRoleAssignmentId $assignment.Id -ErrorAction Stop
        }
    }
}

$scopes = @(
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All"
)

Add-RequiredModules

$null = Connect-MgGraph -Scopes $scopes -TenantId $TenantId

$scopeErrors = Confirm-ContextScopes -Scopes $scopes
if (-not $null -eq $scopeErrors) {
    throw $scopeErrors
}

try {
    $uaiServicePrincipalId = (Get-MgServicePrincipal -Filter "displayName eq '$UAIDisplayName'" -Property Id -ErrorAction Stop | Select-Object -Property Id).Id
}
catch {
    throw "Failed to get User Assigned Identity `"$UAIDisplayName`" from Microsoft Graph. Make sure that the UAI exists."
}

$uaiAssignments = @(Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $uaiServicePrincipalId)

$resources = @(
    @{
        ResourceName = 'Microsoft Graph'
        # Microsoft Graph App ID (DON'T CHANGE)
        AppId        = '00000003-0000-0000-c000-000000000000'
        Permissions  = @(
            "Application.Read.All",
            "User.Read.All",
            "User.EnableDisableAccount.All",
            "User.RevokeSessions.All",
            "User-PasswordProfile.ReadWrite.All",
            "IdentityRiskyUser.ReadWrite.All",
            "Mail.ReadWrite",
            "ThreatHunting.Read.All"
        )
    },
    @{
        ResourceName = 'Microsoft Defender for Endpoint'
        # WindowsDefenderATP (Microsoft Defender for Endpoint) App ID (DON'T CHANGE)
        AppId        = 'fc780465-2017-40d4-a0c5-307022471b92'
        Permissions  = @(
            "Alert.ReadWrite.All",
            "Ip.Read.All",
            "File.Read.All",
            "URL.Read.All",
            "Machine.CollectForensics",
            "Machine.Isolate",
            "Machine.Read.All",
            "Machine.RestrictExecution",
            "Machine.Scan",
            "Machine.StopAndQuarantine",
            "Vulnerability.Read.All",
            "Software.Read.All",
            "User.Read.All",
            "Ti.ReadWrite.All"
            # Replaced by Graph permission "ThreatHunting.Read.All"
            # "AdvancedQuery.Read.All"
        )
    },
    @{
        ResourceName = 'Microsoft 365 Defender'
        # Microsoft Threat Protection (Microsoft Defender XDR) App ID (DON'T CHANGE)
        AppId        = '8ee8fdad-f234-4243-8f3b-15c294843740'
        Permissions  = @(
            # Replaced by Graph permission "ThreatHunting.Read.All"
            # "AdvancedHunting.Read.All"
        )
    }
)

foreach ($resource in $resources) {
    Sync-UAIPermissions -ResourceName $resource.ResourceName -AppId $resource.AppId -Permissions $resource.Permissions `
        -UAIServicePrincipalId $uaiServicePrincipalId -UAIAssignments $uaiAssignments
}
