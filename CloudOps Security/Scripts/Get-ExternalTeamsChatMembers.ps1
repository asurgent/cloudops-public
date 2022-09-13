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
        [guid] $tenantId
    )

    $users = Get-MgUser

    $externalChatMembers = New-Object System.Collections.ArrayList
    
    foreach ($user in $users) {
        Write-Host "Parsing chats for user: $($user.UserPrincipalName)"
        $chats = Get-MgUserChat -UserId $user.Id -ExpandProperty Members
        $chats = $chats | Where-Object { $_.Members.Count -gt 0 }
    
        foreach ($member in $chats.Members) {
            if ($member.AdditionalProperties['tenantId'] -ne $tenantId) {
                $userObject = [PSCustomObject]@{
                    UserId   = $member.AdditionalProperties['userId']
                    Email    = $member.AdditionalProperties['email']
                    Domain   = $member.AdditionalProperties['email'].Split('@')[1]
                    TenantId = $member.AdditionalProperties['tenantId']
                }
    
                [void]$externalChatMembers.Add($userObject)
            }
        }
    }
    
    return $externalChatMembers | Select-Object -Unique
}

$token = (Get-MsalToken -ClientId $clientId -ClientSecret $clientSecret -TenantId $tenantId).AccessToken
Connect-MgGraph -AccessToken $token

if(-not (Test-Path $outpath))
{
    New-Item -Path $outpath -ItemType Directory
}

$externalChatMembers = Get-ExternalTeamsChatMembers -tenantId $tenantId

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