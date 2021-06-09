function Add-RequiredModules {
    if(-not ($aadModule = Get-Module -Name AzureAD -ListAvailable))
    {
        Write-Verbose -Message "Did not find Azure AD module, attempting to install."
        try {
            Install-Module -Name AzureAD -Force -ErrorAction Stop    
        }
        catch {
            throw "Failed to install module 'AzureAD'. Error: $($_.Exception.Message)"
        }
    }
    else
    {
        Write-Verbose -Message "Found AzureAD module version: $($aadModule.Version)"
        Write-Verbose -Message "Importing AzureAD module"
        Import-Module -Name AzureAD

        Write-Verbose -Message "Azure AD module imported. Attempting to connect."
        try 
        {
            $session = Get-AzureADCurrentSessionInfo -ErrorAction Stop
        }
        catch 
        {
            try {
                $null = Connect-AzureAD -TenantId $tenantId
            }
            catch {
                throw "Failed to connect to AzureAD. Error: $($_.Exception.Message)"    
            }
        }
    }
}
function Add-SentinelUAIPermissions {
    param (
        [Parameter(Mandatory = $true)]
        [guid] $tenantId,

        [Parameter(Mandatory = $false)]
        [string] $uaiDisplayName = 'uai-sentinel',

        [Parameter(Mandatory = $false)]
        [bool] $IncludeMDfEPermissions
    )
    begin
    {
        # Microsoft Graph App ID (DON'T CHANGE)
        $graphAppId = "00000003-0000-0000-c000-000000000000"
        $graphPermissions = @(
            "Directory.ReadWrite.All",
            "IdentityRiskyUser.ReadWrite.All"
        )

        # Microsoft Defender for Endpoint App ID (DON'T CHANGE)
        $mdfeAppId = "fc780465-2017-40d4-a0c5-307022471b92"
        $mdfePermissions = @(
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
            "Vulnerability.Read.All"
        )

        Add-RequiredModules
    }
    process
    {
        $errCount = 0
        $uai = Get-AzureADServicePrincipal -Filter "displayName eq '$uaiDisplayName'"
        $graphSPN = Get-AzureADServicePrincipal -Filter "appId eq '$graphAppId'"

        foreach($graphPermission in $graphPermissions)
        {
            Write-Host "Attempting to add permission $graphPermission" -ForegroundColor Cyan
            $graphRole = $graphSPN.AppRoles | Where-Object {$_.Value -eq $graphPermission -and $_.AllowedMemberTypes -contains "Application"}
            try {
                New-AzureAdServiceAppRoleAssignment -ObjectId $uai.ObjectId -PrincipalId $uai.ObjectId -ResourceId $graphSPN.ObjectId -Id $graphRole.Id -ErrorAction Stop    
            }
            catch {
                if($_.Exception.Message -like "*already exists*")
                {
                    Write-Warning -Message "Permission being assigned already exists on the object."
                }
                else
                {
                    Write-Error -Message $_.Exception.Message
                    $errCount++
                }
            }
        }

        if($IncludeMDfEPermissions)
        {
            $mdfeSPN = Get-AzureADServicePrincipal -Filter "appId eq '$mdfeAppId'"
            foreach($mdfePermission in $mdfePermissions)
            {
                Write-Host "Attempting to add role $mdfePermission" -ForegroundColor Cyan
                $mdfeRole = $mdfeSPN.AppRoles | Where-Object {$_.Value -eq $mdfePermission -and $_.AllowedMemberTypes -contains "Application"}
                
                try {
                    New-AzureAdServiceAppRoleAssignment -ObjectId $uai.ObjectId -PrincipalId $uai.ObjectId -ResourceId $mdfeSPN.ObjectId -Id $mdfeRole.Id -ErrorAction Stop    
                }
                catch {
                    if($_.Exception.Message -like "*already exists*")
                    {
                        Write-Warning -Message "Permission being assigned already exists on the object."
                    }
                    else
                    {
                        Write-Error -Message $_.Exception.Message
                        $errCount++
                    }
                }
            }
        }
    }
    end
    {
        if($errCount -eq 0)
        {
            $fgc = 'Green'
        }
        else {
            $fgc = 'Red'
        }
        
        Write-Host "Completed with $errCount errors." -ForegroundColor $fgc
    }
}