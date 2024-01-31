

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


Write-Host "Loading Directory Roles..."


#$PIMRoleAssignments = import-csv .\pimroleassignments.csv
$PIMRoleAssignments = @()

$PIMRoleAssignments += [pscustomobject]@{
    RoleName="Directory Readers"
    ApproversGroupName="PIM_AAD_DIRECTORYREADERS_APPROVERS"
    MaxActivationTimeInHours=8
    AuthContext="c1"
    EnablementRequirements="Justification+Ticketing"
    EnablementAdminAssignment="Justification"
}

$allDirectoryRoles = Get-MgRoleManagementDirectoryRoleDefinition -All 

Get-MgPolicyRoleManagementPolicy -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole'" 


$PIMRoleAssignments | % {

    $RoleName = $_.RoleName
    $ApproversGroupName = $_.ApproversGroupName
    $MaxActivationTimeInHours = $_.MaxActivationTimeInHours
    $AuthContext = $_.AuthContext
    [array]$EnablementRequirements = $_.EnablementRequirements.Split("+")
    [array]$EnablementAdminAssignment = $_.EnablementAdminAssignment.Split("+")


    $role = $allDirectoryRoles | ? { $_.DisplayName -eq $RoleName }

    $assignedpolicy = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'DirectoryRole' and RoleDefinitionId eq '$($role.Id)'" -ExpandProperty "policy(`$expand=rules)"

    if($assignedpolicy.Policy.Id -eq $null) {  
        Write-error "Policy was not found for role $role"
        return
    }

    $assignedpolicy.Policy.Rules | fl


    $RoleName
    $ApproversGroupName
    $MaxActivationTimeInHours
    $AuthContext 
    $EnablementRequirements 
    $EnablementAdminAssignment 

    #$assignedpolicy.Policy.Rules | % {
    #    if($_.id -ne "Approval_EndUser_Assignment") {return}
    #    $rule = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id -UnifiedRoleManagementPolicyRuleId $_.Id 
    #    $rule.AdditionalProperties.setting.approvalStages | fl
    #    $rule | ConvertTo-Json >"$($_.Id).txt"
    #}


    write-host "Assigning Approval_EndUser_Assignment Policy on $RoleName role."

    $group = Get-MgGroup -Filter "displayname eq '$ApproversGroupName'"

    if($group -eq $null) {
        Write-Error "Group $GroupName not found."
        return
    }


    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
        setting = @{
            "@odata.type"="#microsoft.graph.approvalSettings"
            approvalMode="SingleStage"
            isApprovalRequired=$true
            isApprovalRequiredForExtension=$true
            isRequestorJustificationRequired=$true
            approvalStages= @(
                @{
                    "@odata.type"="#microsoft.graph.unifiedApprovalStage"
                    approvalStageTimeOutInDays=1
                    isApproverJustificationRequired=$true
                    escalationTimeInMinutes=0
                    isEscalationEnabled=$false
                    escalationApprovers=@()
                    primaryApprovers= @(
                        @{
                            "@odata.type"="#microsoft.graph.groupMembers"
                            groupId=$group.Id
                            description=$group.DisplayName
                        })
                    }
            )}            
			target = @{
			caller = "EndUser"
			operations = @(
			    "All"
            )
			level = "Assignment"
			inheritableSettings = @(
			)
		    enforcedSettings = @(
            )
	    }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Approval_EndUser_Assignment' `
        -BodyParameter $params



    write-host "Assigning Expiration_EndUser_Assignment Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        isExpirationRequired = $true
        maximumDuration = "PT$($MaxActivationTimeInHours)H"
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "EndUser"
            Operations = @(
                "all"
                )
            Level = "Assignment"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Expiration_EndUser_Assignment' `
        -BodyParameter $params


    write-host "Assigning Expiration_Admin_Assignment Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        isExpirationRequired = $false
        maximumDuration = "P180D"
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "Admin"
            Operations = @(
                "all"
                )
            Level = "Assignment"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Expiration_Admin_Assignment' `
        -BodyParameter $params

    write-host "Assigning AuthenticationContext_EndUser_Assignment Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
        isEnabled = ![string]::IsNullOrEmpty($AuthContext)
        claimValue = $AuthContext
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "EndUser"
            Operations = @(
                "all"
                )
            Level = "Assignment"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'AuthenticationContext_EndUser_Assignment' `
        -BodyParameter $params


    Write-Host "Assigning Enablement_EndUser_Assignment Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
        enabledRules = [array]$EnablementRequirements
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "EndUser"
            Operations = @(
                "all"
                )
            Level = "Assignment"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Enablement_EndUser_Assignment' `
        -BodyParameter $params


    Write-Host "Assigning Enablement_Admin_Assignment Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
        enabledRules = [array]$EnablementAdminAssignment
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "Admin"
            Operations = @(
                "all"
                )
            Level = "Assignment"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Enablement_Admin_Assignment' `
        -BodyParameter $params


    Write-Host "Assigning Enablement_Admin_Eligibility Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        enabledRules = @() 
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "Admin"
            Operations = @(
                "all"
                )
            Level = "Eligibility"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Expiration_Admin_Eligibility' `
        -BodyParameter $params


    Write-Host "Assigning Enablement_Admin_Eligibility Policy on $RoleName role."

    $params = @{
        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
        isExpirationRequired=$false
        maximumDuration="P365D"
        Target = @{
            "@odata.type" = "microsoft.graph.unifiedRoleManagementPolicyRuleTarget"
            Caller = "Admin"
            Operations = @(
                "all"
                )
            Level = "Eligibility"
            InheritableSettings = @(
            )
            EnforcedSettings = @(
        )
        }
    }

    Update-MgPolicyRoleManagementPolicyRule `
        -UnifiedRoleManagementPolicyId $assignedpolicy.Policy.Id `
        -UnifiedRoleManagementPolicyRuleId 'Expiration_Admin_Eligibility' `
        -BodyParameter $params        
}
