param (
    [Parameter(Mandatory = $true)]
    [guid] $TenantId,

    [Parameter(Mandatory = $false)]
    [string] $UAIDisplayName = 'uai-sentinel',

    [Parameter(Mandatory = $false)]
    [bool] $IncludeMDEPermissions
)

function Add-RequiredModules {

    $modules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications"
    )

    foreach($module in $modules)
    {
        if (-not (Get-Module -Name $module -ListAvailable)) {
            Write-Verbose -Message "Did not find module `"$module`", attempting to install."
            try {
                Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop    
            }
            catch {
                throw "Failed to install module `"$module`". Error: $($_.Exception.Message)"
            }
        }

        Write-Verbose -Message "Attempting to importing module `"$module`""
        try {
            Import-Module -Name $module -ErrorAction Stop
        }
        catch {
            throw "Failed to import module `"$module`". Error: $($_.Exception.Message)"
        }
    }
}

function Confirm-ContextScopes
{
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

$scopes = @(
    "Application.Read.All",
    "AppRoleAssignment.ReadWrite.All"
)

Add-RequiredModules

$null = Connect-MgGraph -Scopes $scopes -TenantId $TenantId -ForceRefresh

$scopeErrors = Confirm-ContextScopes -Scopes $scopes
if (-not $null -eq $scopeErrors)
{
    throw $scopeErrors
}

try {
    $uaiServicePrincipalId = (Get-MgServicePrincipal -Filter "displayName eq '$UAIDisplayName'" -Property Id -ErrorAction Stop | Select-Object -Property Id).Id    
}
catch {
    throw "Failed to get User Assigned Identity `"$UAIDisplayName`" from Microsoft Graph. Make sure that the UAI exists."
}

$uaiAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $uaiServicePrincipalId

# Microsoft Graph App ID (DON'T CHANGE)
$graphAppId = "00000003-0000-0000-c000-000000000000"
$graphSPN = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"

$graphPermissions = @(
    "Directory.ReadWrite.All",
    "IdentityRiskyUser.ReadWrite.All"
)

$graphPermissionRoles = $graphSPN.AppRoles | Where-Object { $_.Value -in $graphPermissions}
$currentGraphUaiAssignments = $uaiAssignments | Where-Object { $_.ResourceId -eq $graphSPN.Id }

foreach ($graphPermissionRole in $graphPermissionRoles)
{
    if ($graphPermissionRole.Id -notin $currentGraphUaiAssignments.AppRoleId)
    {
        $permission = @{
            principalId = $uaiServicePrincipalId
            resourceId = $graphSPN.Id
            appRoleId = $graphPermissionRole.Id
        }

        try {
            Write-Host "Attempting to add Microsoft Graph permission `"$($graphPermissionRole.Value)`" to UAI." -ForegroundColor Cyan -NoNewline
            $null = New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $graphSPN.Id -BodyParameter $permission -ErrorAction Stop
            Write-Host " - Success!" -ForegroundColor Green
        }
        catch {
            Write-Host " - Failed!" -ForegroundColor Red
            Write-Warning -Message "Failed to add Microsoft Graph permission $($graphPermissionRole.Value). Error: $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "Microsoft Graph permission `"$($graphPermissionRole.Value)`" is already assigned to UAI." -ForegroundColor Green
    }
}

if($IncludeMDEPermissions)
{
    # Microsoft Defender for Endpoint App ID (DON'T CHANGE)
    $mdeAppId = "fc780465-2017-40d4-a0c5-307022471b92"
    $mdeSPN = Get-MgServicePrincipal -Filter "appId eq '$mdeAppId'"

    $mdePermissions = @(
        "Alert.Read.All",
        "Ip.Read.All",
        "File.Read.All",
        "URL.Read.All",
        "Machine.CollectForensics",
        "Machine.Isolate",
        "Machine.Read.All",
        "Machine.RestrictExecution",
        "Machine.Scan",
        "Machine.StopAndQuarantine",
        "Machine.LiveResponse",
        "Vulnerability.Read.All",
        "Software.Read.All",
        "User.Read.All",
        "AdvancedQuery.Read.All"
    )

    $mdePermissionRoles = $mdeSPN.AppRoles | Where-Object { $_.Value -in $mdePermissions }
    $currentmdeUaiAssignments = $uaiAssignments | Where-Object { $_.ResourceId -eq $mdeSPN.Id }

    foreach ($mdePermissionRole in $mdePermissionRoles) {
        if ($mdePermissionRole.Id -notin $currentmdeUaiAssignments.AppRoleId) {
            $permission = @{
                principalId = $uaiServicePrincipalId
                resourceId  = $mdeSPN.Id
                appRoleId   = $mdePermissionRole.Id
            }

            try {
                Write-Host "Attempting to add Microsoft Defender for Endpoint permission `"$($mdePermissionRole.Value)`" to UAI." -ForegroundColor Cyan -NoNewline
                $null = New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $mdeSPN.Id -BodyParameter $permission -ErrorAction Stop
                Write-Host " - Success!" -ForegroundColor Green
            }
            catch {
                Write-Host " - Failed!" -ForegroundColor Red
                Write-Warning -Message "Failed to add Microsoft Defender for Endpoint permission $($mdePermissionRole.Value). Error: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Microsoft Defender for Endpoint permission `"$($mdePermissionRole.Value)`" is already assigned to UAI." -ForegroundColor Green
        }
    }

    # Microsoft 365 Defender App ID (DON'T CHANGE)
    $mdAppId = "8ee8fdad-f234-4243-8f3b-15c294843740"
    $mdSPN = Get-MgServicePrincipal -Filter "appId eq '$mdAppId'"

    $mdPermissions = @(
        "AdvancedHunting.Read.All"
    )

    $mdPermissionRoles = $mdSPN.AppRoles | Where-Object { $_.Value -in $mdPermissions }
    $currentmdUaiAssignments = $uaiAssignments | Where-Object { $_.ResourceId -eq $mdSPN.Id }

    foreach ($mdPermissionRole in $mdPermissionRoles) {
        if ($mdPermissionRole.Id -notin $currentmdUaiAssignments.AppRoleId) {
            $permission = @{
                principalId = $uaiServicePrincipalId
                resourceId  = $mdSPN.Id
                appRoleId   = $mdPermissionRole.Id
            }

            try {
                Write-Host "Attempting to add Microsoft 365 Defender permission `"$($mdPermissionRole.Value)`" to UAI." -ForegroundColor Cyan -NoNewline
                $null = New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $mdSPN.Id -BodyParameter $permission -ErrorAction Stop
                Write-Host " - Success!" -ForegroundColor Green
            }
            catch {
                Write-Host " - Failed!" -ForegroundColor Red
                Write-Warning -Message "Failed to add Microsoft 365 Defender permission $($mdPermissionRole.Value). Error: $($_.Exception.Message)"
            }
        }
        else {
            Write-Host "Microsoft 365 Defender permission `"$($mdPermissionRole.Value)`" is already assigned to UAI." -ForegroundColor Green
        }
    }
}