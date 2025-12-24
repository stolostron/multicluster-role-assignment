/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1beta1

// ConditionType represents the type of condition for a MulticlusterRoleAssignment.
type ConditionType string

// Condition types for MulticlusterRoleAssignment status. These represent the overall state of the
// MulticlusterRoleAssignment resource.
const (
	// ConditionTypeApplied indicates whether the controller successfully completed applying role assignments to all
	// target clusters. This reflects the controller's apply operation. For overall role assignment health, check the
	// Ready condition.
	//
	// Status values:
	//   - True: Controller successfully applied to all target clusters
	//   - False: Controller failed to apply to some or all target clusters
	//   - Unknown: Application status cannot be determined or is in progress
	ConditionTypeApplied ConditionType = "Applied"

	// ConditionTypeReady is the top-level condition indicating overall operational status. This condition is computed
	// based on the Applied condition and individual RoleAssignment statuses.
	//
	// Status values:
	//   - True: Resource is ready and all role assignments are active
	//   - False: Problems detected (failures or pending operations)
	//   - Unknown: Unable to determine ready status
	ConditionTypeReady ConditionType = "Ready"
)

// ConditionReason represents the reason for a condition's status.
type ConditionReason string

// Reasons for ConditionTypeApplied. These explain why the Applied condition has a particular status.
const (
	// ReasonAppliedSuccessfully indicates role assignments were successfully applied to all target clusters.
	ReasonAppliedSuccessfully ConditionReason = "AppliedSuccessfully"

	// ReasonApplyFailed indicates role assignment application failed.
	ReasonApplyFailed ConditionReason = "ApplyFailed"

	// ReasonApplyInProgress indicates role assignment application is currently in progress.
	ReasonApplyInProgress ConditionReason = "ApplyInProgress"
)

// Reasons for ConditionTypeReady. These explain why the Ready condition has a particular status. Ready condition
// reasons focus on RoleAssignment-level health, not cluster operations.
const (
	// ReasonAllAssignmentsReady indicates all role assignments are active and healthy.
	ReasonAllAssignmentsReady ConditionReason = "AllAssignmentsReady"

	// ReasonAssignmentsPending indicates some role assignments are still being processed.
	ReasonAssignmentsPending ConditionReason = "AssignmentsPending"

	// ReasonAssignmentsPartialFailure indicates some role assignments are in error state.
	ReasonAssignmentsPartialFailure ConditionReason = "AssignmentsPartialFailure"

	// ReasonProvisioningFailed indicates role assignments could not be provisioned. This occurs when the controller
	// fails to apply the desired state to target clusters (Applied condition is False).
	ReasonProvisioningFailed ConditionReason = "ProvisioningFailed"
)

// RoleAssignmentStatusType represents the status of a RoleAssignment.
type RoleAssignmentStatusType string

// RoleAssignment status types. These represent the state of individual RoleAssignments within a
// MulticlusterRoleAssignment.
const (
	// StatusTypePending indicates the role assignment is being initialized or processed.
	StatusTypePending RoleAssignmentStatusType = "Pending"

	// StatusTypeActive indicates the role assignment has been successfully applied to all target clusters.
	StatusTypeActive RoleAssignmentStatusType = "Active"

	// StatusTypeError indicates the role assignment encountered an error.
	StatusTypeError RoleAssignmentStatusType = "Error"
)

// RoleAssignmentStatusReason represents the reason for a RoleAssignment's status.
type RoleAssignmentStatusReason string

// Reasons for RoleAssignment status. These explain why a particular RoleAssignment has its current status.
const (
	// ReasonProcessing indicates the role assignment is being processed.
	ReasonProcessing RoleAssignmentStatusReason = "Processing"

	// ReasonInvalidReference indicates a referenced resource does not exist.
	ReasonInvalidReference RoleAssignmentStatusReason = "InvalidReference"

	// ReasonNoMatchingClusters indicates the placement exists but matches zero clusters.
	ReasonNoMatchingClusters RoleAssignmentStatusReason = "NoMatchingClusters"

	// ReasonDependencyNotReady indicates an external dependency is not ready.
	ReasonDependencyNotReady RoleAssignmentStatusReason = "DependencyNotReady"

	// ReasonSuccessfullyApplied indicates the role assignment was successfully applied to all target clusters.
	ReasonSuccessfullyApplied RoleAssignmentStatusReason = "SuccessfullyApplied"

	// ReasonApplicationFailed indicates the role assignment application failed.
	ReasonApplicationFailed RoleAssignmentStatusReason = "ApplicationFailed"
)
