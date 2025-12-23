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
	// ConditionTypeApplied indicates whether ClusterPermission resources have been successfully created/updated across
	// all target clusters.
	//
	// Status values:
	//   - True: All ClusterPermissions applied successfully
	//   - False: Some or all ClusterPermissions failed to apply
	//   - Unknown: Unable to determine application status
	ConditionTypeApplied ConditionType = "Applied"

	// ConditionTypeReady is the top-level condition indicating overall operational status. This condition is computed
	// based on other conditions and RoleAssignment statuses.
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
	// ReasonClusterPermissionApplied indicates ClusterPermissions were applied successfully.
	ReasonClusterPermissionApplied ConditionReason = "ClusterPermissionApplied"

	// ReasonClusterPermissionFailed indicates ClusterPermission application failed.
	ReasonClusterPermissionFailed ConditionReason = "ClusterPermissionFailed"

	// ReasonApplyInProgress indicates ClusterPermission application is in progress.
	ReasonApplyInProgress ConditionReason = "ApplyInProgress"
)

// Reasons for ConditionTypeReady. These explain why the Ready condition has a particular status.
const (
	// ReasonPartialFailure indicates some role assignments failed.
	ReasonPartialFailure ConditionReason = "PartialFailure"

	// ReasonInProgress indicates role assignments are still being processed.
	ReasonInProgress ConditionReason = "InProgress"

	// ReasonAllApplied indicates all role assignments are active.
	ReasonAllApplied ConditionReason = "AllApplied"

	// ReasonApplyFailed indicates the apply operation failed.
	ReasonApplyFailed ConditionReason = "ApplyFailed"

	// ReasonUnknown indicates the status cannot be determined.
	ReasonUnknown ConditionReason = "Unknown"
)

// RoleAssignmentStatusType represents the status of a RoleAssignment.
type RoleAssignmentStatusType string

// RoleAssignment status types. These represent the state of individual RoleAssignments within a
// MulticlusterRoleAssignment.
const (
	// StatusTypePending indicates the role assignment is being initialized or processed.
	StatusTypePending RoleAssignmentStatusType = "Pending"

	// StatusTypeActive indicates the role assignment has been successfully applied.
	StatusTypeActive RoleAssignmentStatusType = "Active"

	// StatusTypeError indicates the role assignment encountered an error.
	StatusTypeError RoleAssignmentStatusType = "Error"
)

// RoleAssignmentStatusReason represents the reason for a RoleAssignment's status.
type RoleAssignmentStatusReason string

// Reasons for RoleAssignment status. These explain why a particular RoleAssignment has its current status.
const (
	// ReasonInitializing indicates the role assignment is being initialized.
	ReasonInitializing RoleAssignmentStatusReason = "Initializing"

	// ReasonAggregatingClusters indicates clusters are being resolved from placements.
	ReasonAggregatingClusters RoleAssignmentStatusReason = "AggregatingClusters"

	// ReasonClustersValid indicates all target clusters have been validated.
	ReasonClustersValid RoleAssignmentStatusReason = "ClustersValid"

	// ReasonPlacementResolutionFailed indicates cluster resolution from placements failed.
	ReasonPlacementResolutionFailed RoleAssignmentStatusReason = "PlacementResolutionFailed"

	// ReasonNoClustersResolved indicates no clusters matched the placement criteria.
	ReasonNoClustersResolved RoleAssignmentStatusReason = "NoClustersResolved"

	// ReasonPlacementNotFound indicates a referenced placement resource was not found.
	ReasonPlacementNotFound RoleAssignmentStatusReason = "PlacementNotFound"

	// ReasonRAClusterPermissionApplied indicates ClusterPermissions were applied successfully for this role assignment.
	// todo: these were shared with conditions; reconsider/delete
	ReasonRAClusterPermissionApplied RoleAssignmentStatusReason = "ClusterPermissionApplied"

	// ReasonRAClusterPermissionFailed indicates ClusterPermission application failed for this role assignment.
	// todo: these were shared with conditions; reconsider/delete
	ReasonRAClusterPermissionFailed RoleAssignmentStatusReason = "ClusterPermissionFailed"
)
