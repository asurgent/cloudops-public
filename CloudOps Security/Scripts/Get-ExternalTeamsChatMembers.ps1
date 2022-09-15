#Requires -Modules Microsoft.Graph, MSAL.PS -PSEdition Core
param (
    [Parameter(Mandatory)]
    [guid] $tenantId,

    [Parameter(Mandatory)]
    [string] $clientId,

    [Parameter(Mandatory)]
    [securestring] $clientSecret,

    [Parameter(Mandatory = $false)]
    [string] $outpath = "C:\Temp"
)

function Get-ExternalTeamsChatMembers {
    param (
        [Parameter(Mandatory)]
        [guid] $tenantId,

        [Parameter(Mandatory)]
        [string] $clientId,
    
        [Parameter(Mandatory)]
        [securestring] $clientSecret
    )

    $token = Get-MsalToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId
    Connect-MgGraph -AccessToken $token.AccessToken

    try {
        $users = Get-MgUser -All    
    }
    catch {
        throw "Failed to get users from Graph. Error: $($_.Exception.Message)"
    }
    

    $externalChatMembers = New-Object System.Collections.ArrayList
    
    foreach ($user in $users) {
        $tokenExpiresInMinutes = ($token.ExpiresOn.LocalDateTime - (Get-Date)).Minutes
        if($tokenExpiresInMinutes -lt 5)
        {
            Write-Host "Graph token expires in 5 minutes, attempting refresh..." -ForegroundColor Cyan
            try {
                $token = Get-MsalToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId -ForceRefresh
                Write-Host -Message "Token refreshed..." -ForegroundColor Cyan
            }
            catch {
                Write-Error -Message "Failed to refresh Graph token! Error: $($_.Exception.Message)"
            }
        }

        Write-Host "Parsing chats for user: $($user.UserPrincipalName)"
        try {
            $chats = Get-MgUserChat -UserId $user.Id -ExpandProperty Members
            $chats = $chats | Where-Object { $_.Members.Count -gt 0 }
        
            foreach ($member in $chats.Members) {
                if ($member.AdditionalProperties['tenantId'] -ne $tenantId) {
                    $userObject = [PSCustomObject]@{
                        UserId   = $member.AdditionalProperties['userId']
                        Email    = $member.AdditionalProperties['email']
                        Domain   = if(-not [string]::IsNullOrWhiteSpace($member.AdditionalProperties['email'])) { $member.AdditionalProperties['email'].Split('@')[1] }
                        TenantId = $member.AdditionalProperties['tenantId']
                    }
        
                    [void]$externalChatMembers.Add($userObject)
                }
            }
        }
        catch {
            Write-Error -Message "Failed to get chats for user $($user.UserPrincipalName). Error: $($_.Exception.Message)"
        }
    }

    return $externalChatMembers | Select-Object -Unique -Property UserId, Email, Domain, TenantId
}

if(-not (Test-Path $outpath))
{
    New-Item -Path $outpath -ItemType Directory
}

$externalChatMembers = (Get-ExternalTeamsChatMembers -tenantId $tenantId -clientId $clientId -clientSecret $clientSecret) | Select-Object -Property UserId, Email, Domain, TenantId
$externalChatMembers = $externalChatMembers | Where-Object {$null -ne $_.Email}

$color = if($externalChatMembers.Count -gt 0) {"DarkYellow"} else {"Green"}
Write-Host -ForegroundColor $color "Found $($externalChatMembers.Count) external chat members."

try {
    $externalChatMembers | Export-Csv -Path "$outpath/external_chat_members.csv" -Encoding utf8 -NoClobber -Delimiter ';' -Force
    Write-Host -ForegroundColor Green "Exported results to $outpath/external_chat_members.csv"
}
catch {
    Write-Error -Message "Failed to export results to $($outpath)/external_chat_members.csv. Error: $($_.Exception.Message)"
    $externalChatMembers
}