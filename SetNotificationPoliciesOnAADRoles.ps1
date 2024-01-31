

###  Script will assignment members (RoleAssignable groups ideally) to AAD PIM roles. 


function New-NotificationTemplate
{
    param(
        [parameter(mandatory)][validateset("Admin", "EndUser")]
        $Caller,
        [parameter(mandatory)][validateset("Assignment", "Eligibility")]
        $Level,
        [parameter(mandatory)][validateset("Email", "Eligibility")]
        $notificationType,
        [parameter(mandatory)][validateset("Admin", "EndUser", "Approver", "Requestor")]
        $recipientType,
        [parameter(mandatory)][validateset("All", "Critical")]
        $notificationLevel = "Critical",
        [bool]$isDefaultRecipientsEnabled,
        [string[]]$notificationRecipients = @()
    )


     @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyNotificationRule"
        notificationType=$notificationType
        recipientType=$recipientType
        notificationLevel=$notificationLevel
        isDefaultRecipientsEnabled=$isDefaultRecipientsEnabled
        notificationRecipients=$notificationRecipients
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = $Caller
            Operations = @(
                "all"
                )
            Level = $Level
            InheritableSettings = @(
            )
            EnforcedSettings = @(
            )
        }
    }
}




ipmo Microsoft.Graph.Identity.Governance
ipmo Microsoft.Graph.Identity.SignIns
ipmo Microsoft.Graph.Authentication
ipmo Microsoft.Graph.Groups

$Error.Clear()

$Scopes = @(
    "RoleManagement.ReadWrite.Directory"
)

Connect-MgGraph -scopes $scopes -NoWelcome

Write-Host "Loading Directory Roles..."


#$PIMRoleAssignments = import-csv .\pimroleassignments.csv
$PIMRoleAssignments = @()

$PIMRoleAssignments += [pscustomobject]@{
    RoleName="Directory Readers"
    Notification_Admin_EndUser_Assignment=$true
}

$allDirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition -All 

Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" 

$role = $allDirectoryRoles | ? { $_.DisplayName -eq "Directory Readers" }

$assignedpolicy = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and RoleDefinitionId eq '$($role.Id)'" -ExpandProperty "policy(`$expand=rules)"

$assignedpolicy.Policy.Rules | fl

$assignedpolicy.Policy.Rules | % {

    if($_.id -ne "Approval_EndUser_Assignment") {return}
    
    $rule = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id -UnifiedRoleManagementPolicyRuleId $_.Id 
    $rule.AdditionalProperties.setting.approvalStages | fl
    #$rule | ConvertTo-Json >"$($_.Id).txt"
}


$PIMRoleAssignments | % {

    $RoleName = $_.RoleName
    $ApproversGroupName = $_.ApproversGroupName
    $MaxActivationTimeInHours = $_.MaxActivationTimeInHours
    $AuthContext = $_.AuthContext
    $EnablementRequirements = $_.EnablementRequirements
    $EnablementAdminAssignment = $_.EnablementAdminAssignment

    write-host "Assigning Notification_Admin_EndUser_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller EndUser `
        -notificationType Email `
        -Level Assignment  `
        -recipientType Admin `
        -notificationLevel Critical `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_EndUser_Assignment' `
        -BodyParameter $params


    write-host "Assigning Notification_Admin_Admin_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -notificationType Email `
        -Level Assignment  `
        -recipientType Admin `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_Admin_Assignment' `
        -BodyParameter $params


    write-host "Assigning Notification_Admin_Admin_Eligibility Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -notificationType Email `
        -Level Eligibility  `
        -recipientType Admin `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Admin_Admin_Eligibility' `
        -BodyParameter $params



    write-host "Assigning Notification_Approver_Admin_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -notificationType Email `
        -Level Assignment  `
        -recipientType Approver `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_Admin_Assignment' `
        -BodyParameter $params
        

    write-host "Assigning Notification_Approver_Admin_Eligibility Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -Level Eligibility  `
        -notificationType Email `
        -recipientType Approver `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_Admin_Eligibility' `
        -BodyParameter $params
        

    
    write-host "Assigning Notification_Approver_EndUser_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller EndUser `
        -Level Assignment  `
        -notificationType Email `
        -recipientType Approver `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Approver_EndUser_Assignment' `
        -BodyParameter $params



    write-host "Assigning Notification_Requestor_Admin_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -Level Assignment  `
        -notificationType Email `
        -recipientType Requestor `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_Admin_Assignment' `
        -BodyParameter $params



    write-host "Assigning Notification_Requestor_Admin_Eligibility Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller Admin `
        -Level Eligibility  `
        -notificationType Email `
        -recipientType Requestor `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_Admin_Eligibility' `
        -BodyParameter $params



    write-host "Assigning Notification_Requestor_EndUser_Assignment Policy on $RoleName role."

    $params = New-NotificationTemplate -Caller EndUser `
        -Level Assignment  `
        -notificationType Email `
        -recipientType Requestor `
        -notificationLevel All `
        -isDefaultRecipientsEnabled $true

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Notification_Requestor_EndUser_Assignment' `
        -BodyParameter $params
        
        

}

