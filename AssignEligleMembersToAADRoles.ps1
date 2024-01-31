

###  Script will assignment members (RoleAssignable groups ideally) to AAD PIM roles. 

ipmo Microsoft.Graph.Identity.Governance
ipmo Microsoft.Graph.Identity.SignIns
ipmo Microsoft.Graph.Authentication
ipmo Microsoft.Graph.Groups

$Error.Clear()

$Scopes = @(
    "RoleManagement.ReadWrite.Directory"
)

Connect-MgGraph -scopes $scopes -NoWelcome

#$PIMRoleAssignments = import-csv .\pimroleassignments.csv
$PIMRoleAssignments = @()

$PIMRoleAssignments += [pscustomobject]@{
    "RoleName"="Directory Readers"
    "GroupName"="PIM_AAD_DIRECTORYREADERS_ELIGILE"
}

Write-Host "Loading Directory Roles..."
$allDirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition -All

$PIMRoleAssignments | % {

    $GroupName = $_.GroupName
    $RoleName  = $_.RoleName  
    write-host "Assigning $GroupName as eligible to $RoleName role."

    $group = Get-MgGroup -Filter "displayname eq '$GroupName'"

    if($group -eq $null) {
        Write-Host "Group $GroupName not found.  Creating ..."
        $group = New-MgGroup -SecurityEnabled -DisplayName $GroupName -IsAssignableToRole -MailEnabled:$false -MailNickname $GroupName
    }

    if(!$group.IsAssignableToRole) {
        Write-Error "Group $GroupName is not role assignable."
        return
    }

    $role = $allDirectoryRoles | ? { $_.DisplayName -eq $RoleName }
    if($role -eq $null) {
        Write-Error "Role $RoleName was not found in the tenant."
        return
    }

    # todo: might want to check active / permanent assignments
    #$activeRoleAssigments = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -Filter "roleDefinitionId eq '$($role.Id)'" -Property "principalid" -ExpandProperty "principal"
    #$activeRoleAssigments.Principal.AdditionalProperties.displayName


    $eligibleRoleAssignments = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -Filter "roleDefinitionId eq '$($role.Id)'" -Property "principalid" -ExpandProperty "principal"

    if($eligibleRoleAssignments.PrincipalId -eq $group.Id)
    {
        write-host "$GroupName already eligible for $RoleName role."
        return
    }

    # Assign Group as Eliglibe Role and Policy
    $params = @{
	    action = "adminAssign"
	    justification = "Assign $GroupName to $RoleName"
	    roleDefinitionId = $role.Id
	    directoryScopeId = "/"
	    principalId = $group.Id
	    scheduleInfo = @{
		    startDateTime = [System.DateTime]::UtcNow
		    expiration = @{
			    type = "NoExpiration"
		    }
	    }
    }
     
    New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest  -BodyParameter $params

}





