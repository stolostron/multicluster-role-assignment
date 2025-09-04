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

package controller

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterv1beta2 "open-cluster-management.io/api/cluster/v1beta2"
	clusterpermissionv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Condition types
const (
	// ConditionTypeValidated indicates whether the MulticlusterRoleAssignment spec has been validated.
	// Status: True = spec is valid, False = spec is not valid, Unknown = unable to validate
	ConditionTypeValidated = "Validated"

	// ConditionTypeApplied indicates whether the ClusterPermission resources have been successfully created/updated
	// across all target clusters.
	// Status: True = all ClusterPermissions applied, False = some/all ClusterPermissions not applied, Unknown = unable
	// to determine ClusterPermissions applied condition
	ConditionTypeApplied = "Applied"

	// ConditionTypeReady is the top-level condition indicating overall operational status.
	// Status: True = ready and working, False = problems detected, Unknown = unable to determine ready condition
	ConditionTypeReady = "Ready"
)

// ConditionTypeValidated related constants
const (
	// ConditionTypeValidated Reasons
	ReasonInvalidSpec = "InvalidSpec"
	ReasonSpecIsValid = "SpecIsValid"

	// ConditionTypeValidated Messages
	MessageSpecValidationPassed = "Spec validation passed"
	MessageSpecValidationFailed = "Spec validation failed"
)

// ConditionTypeApplied related constants
const (
// ConditionTypeApplied Reasons
// TODO: Add ConditionTypeApplied reason constants

// ConditionTypeApplied Messages
// TODO: Add ConditionTypeApplied message constants
)

// ConditionTypeReady related constants
const (
	// ConditionTypeReady Reasons
	ReasonPartialFailure = "PartialFailure"
	ReasonInProgress     = "InProgress"
	ReasonAllApplied     = "AllApplied"
	ReasonApplyFailed    = "ApplyFailed"
	ReasonUnknown        = "Unknown"

	// ConditionTypeReady Messages
	MessageStatusCannotBeDetermined           = "Status cannot be determined"
	MessageRoleAssignmentsFailed              = "role assignments failed"
	MessageRoleAssignmentsPending             = "role assignments pending"
	MessageRoleAssignmentsAppliedSuccessfully = "role assignments applied successfully"
)

// RoleAssignmentStatus related constants
const (
	// RoleAssignmentStatus Statuses
	StatusTypePending = "Pending"
	StatusTypeActive  = "Active"
	StatusTypeError   = "Error"

	// RoleAssignmentStatus Reasons
	ReasonInitializing        = "Initializing"
	ReasonMissingClusterSets  = "MissingClusterSets"
	ReasonClusterSetValid     = "ClusterSetValid"
	ReasonDiscoveringClusters = "DiscoveringClusters"
	ReasonClustersDiscovered  = "ClustersDiscovered"
	ReasonNoClustersFound     = "NoClustersFound"

	// RoleAssignmentStatus Messages
	MessageInitializingRoleAssignment        = "Initializing role assignment"
	MessageMissingManagedClusterSets         = "Missing managed cluster sets"
	MessageManagedClusterSetValidationPassed = "Managed cluster set validation passed"
	MessageDiscoveringTargetClusters         = "Discovering managed clusters"
	MessageNoClustersFoundInClusterSets      = "No managed clusters found in specified managed cluster sets"
	MessageManagedClustersDiscovered         = "Managed clusters discovered"
)

// ClusterPermission management constants
const (
	ClusterPermissionManagedByLabel = "rbac.open-cluster-management.io/managed-by"
	ClusterPermissionManagedByValue = "multiclusterroleassignment-controller"
	ClusterPermissionManagedName    = "mra-managed-permissions"
)

// TODO: Make error constants for validateSpec functions

// MulticlusterRoleAssignmentReconciler reconciles a MulticlusterRoleAssignment object.
type MulticlusterRoleAssignmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=clusterpermissions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=managedclustersets,verbs=get;list;watch
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=managedclusters,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MulticlusterRoleAssignmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	log.Info("Starting reconciliation", "multiclusterroleassignment", req.NamespacedName)

	// Get the MulticlusterRoleAssignment resource
	var mra rbacv1alpha1.MulticlusterRoleAssignment
	if err := r.Get(ctx, req.NamespacedName, &mra); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("MulticlusterRoleAssignment resource not found, skipping reconciliation")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get MulticlusterRoleAssignment")
		return ctrl.Result{}, err
	}

	// Validate spec and update status
	if err := r.validateSpec(ctx, &mra); err != nil {
		log.Error(err, "MulticlusterRoleAssignment spec validation failed")

		reason := ReasonInvalidSpec
		if strings.Contains(err.Error(), "missing ManagedClusterSets") {
			reason = ReasonMissingClusterSets
		}

		r.setCondition(&mra, ConditionTypeValidated, metav1.ConditionFalse, reason, fmt.Sprintf("%s: %s",
			MessageSpecValidationFailed, err.Error()))
		if statusErr := r.updateStatus(ctx, &mra); statusErr != nil {
			log.Error(statusErr, "Failed to update status after validation failure")
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, err
	}

	r.setCondition(&mra, ConditionTypeValidated, metav1.ConditionTrue, ReasonSpecIsValid, MessageSpecValidationPassed)
	if err := r.updateStatus(ctx, &mra); err != nil {
		log.Error(err, "Failed to update status after validation success")
		return ctrl.Result{}, err
	}

	log.Info("Successfully validated MulticlusterRoleAssignment spec", "multiclusterroleassignment", req.NamespacedName)

	managedClusters, err := r.discoverManagedClusters(ctx, &mra)
	if err != nil {
		log.Error(err, "Failed to discover managed clusters")
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, &mra); err != nil {
		log.Error(err, "Failed to update status after cluster discovery")
		return ctrl.Result{}, err
	}

	log.Info("Successfully discovered managed clusters", "multiclusterroleassignment", req.NamespacedName,
		"managedclusters", managedClusters)
	return ctrl.Result{}, nil
}

// validateSpec performs validation on the MulticlusterRoleAssignment spec.
func (r *MulticlusterRoleAssignmentReconciler) validateSpec(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	// Check for duplicate RoleAssignment names (they are not valid and should be blocked by validating webhook)
	namesMap := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if namesMap[roleAssignment.Name] {
			return fmt.Errorf("duplicate role assignment name found: %s", roleAssignment.Name)
		}
		namesMap[roleAssignment.Name] = true
	}

	return r.validateClusterSets(ctx, mra)
}

// validateClusterSets validates that all referenced ManagedClusterSets exist and updates role assignment statuses
// accordingly.
func (r *MulticlusterRoleAssignmentReconciler) validateClusterSets(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	log := logf.FromContext(ctx)

	var allMissingClusterSets []string

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		var missingClusterSetsForRA []string

		for _, clusterSet := range roleAssignment.ClusterSets {
			var clusterSetGetResults clusterv1beta2.ManagedClusterSet
			err := r.Get(ctx, client.ObjectKey{Name: clusterSet}, &clusterSetGetResults)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Error(err, "Referenced ManagedClusterSet not found", "clusterSet", clusterSet, "roleAssignment",
						roleAssignment.Name)
					missingClusterSetsForRA = append(missingClusterSetsForRA, clusterSet)
					allMissingClusterSets = append(allMissingClusterSets, clusterSet)
				} else {
					log.Error(err, "Failed to get ManagedClusterSet", "clusterSet", clusterSet, "roleAssignment",
						roleAssignment.Name)
					return fmt.Errorf("failed to validate cluster set %s: %w", clusterSet, err)
				}
			}
		}

		if len(missingClusterSetsForRA) > 0 {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypeError, ReasonMissingClusterSets,
				fmt.Sprintf("%s: %v", MessageMissingManagedClusterSets, missingClusterSetsForRA))
		} else {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonClusterSetValid,
				MessageManagedClusterSetValidationPassed)
		}
	}

	if len(allMissingClusterSets) > 0 {
		return fmt.Errorf("missing ManagedClusterSets: %v", allMissingClusterSets)
	}

	return nil
}

// TODO: Refactor to improve efficiency - validateClusterSets and discoverManagedClusters both loop over

// discoverManagedClusters discovers all ManagedCluster resources from the specified ManagedClusterSets and returns a
// deduplicated list of cluster names. Updates role assignment statuses during discovery.
func (r *MulticlusterRoleAssignmentReconciler) discoverManagedClusters(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) ([]string, error) {
	log := logf.FromContext(ctx)

	var allClusters []string
	allClustersMap := make(map[string]bool)

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonDiscoveringClusters,
			MessageDiscoveringTargetClusters)

		var clustersInRA []string
		for _, clusterSetName := range roleAssignment.ClusterSets {
			var clusterSet clusterv1beta2.ManagedClusterSet
			err := r.Get(ctx, client.ObjectKey{Name: clusterSetName}, &clusterSet)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Error(err, "ManagedClusterSet not found during discovery", "clusterSet", clusterSetName)
					continue
				}
				return nil, fmt.Errorf("failed to get ManagedClusterSet %s: %w", clusterSetName, err)
			}

			var managedClusterList clusterv1.ManagedClusterList
			labelSelector := client.MatchingLabels{
				"cluster.open-cluster-management.io/clusterset": clusterSetName,
			}

			err = r.List(ctx, &managedClusterList, labelSelector)
			if err != nil {
				return nil, fmt.Errorf("failed to list ManagedClusters for cluster set %s: %w", clusterSetName, err)
			}

			var clustersInSet []string
			for _, cluster := range managedClusterList.Items {
				clustersInSet = append(clustersInSet, cluster.Name)
				clustersInRA = append(clustersInRA, cluster.Name)
				if !allClustersMap[cluster.Name] {
					allClustersMap[cluster.Name] = true
					allClusters = append(allClusters, cluster.Name)
				}
			}

			log.Info("Discovered clusters for cluster set", "clusterSet", clusterSetName, "clusterCount",
				len(clustersInSet), "clusters", clustersInSet)
		}

		if len(clustersInRA) > 0 {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonClustersDiscovered,
				fmt.Sprintf("%s: %v", MessageManagedClustersDiscovered, clustersInRA))
		} else {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonNoClustersFound,
				MessageNoClustersFoundInClusterSets)
		}
	}

	log.Info("Total unique clusters discovered", "clusterCount", len(allClusters))
	return allClusters, nil
}

// getClusterPermission fetches the managed ClusterPermission for a specific cluster namespace. Returns nil if not
// found or if it doesn't have the management label.
func (r *MulticlusterRoleAssignmentReconciler) getClusterPermission(ctx context.Context, clusterNamespace string) (
	*clusterpermissionv1alpha1.ClusterPermission, error) {
	log := logf.FromContext(ctx)

	var clusterPermission clusterpermissionv1alpha1.ClusterPermission
	err := r.Get(ctx, client.ObjectKey{
		Name:      ClusterPermissionManagedName,
		Namespace: clusterNamespace,
	}, &clusterPermission)

	if err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("ClusterPermission not found", "namespace", clusterNamespace, "name", ClusterPermissionManagedName)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get ClusterPermission: %w", err)
	}

	if !r.isClusterPermissionManaged(&clusterPermission) {
		err := fmt.Errorf("ClusterPermission found but not managed by this controller in namespace %s with name %s",
			clusterNamespace, ClusterPermissionManagedName)
		log.Error(err, "ClusterPermission conflict detected", "namespace", clusterNamespace, "name",
			ClusterPermissionManagedName)
		return nil, err
	}

	return &clusterPermission, nil
}

// isClusterPermissionManaged checks if a ClusterPermission has the correct management label
func (r *MulticlusterRoleAssignmentReconciler) isClusterPermissionManaged(
	cp *clusterpermissionv1alpha1.ClusterPermission) bool {
	if cp.Labels == nil {
		return false
	}
	return cp.Labels[ClusterPermissionManagedByLabel] == ClusterPermissionManagedByValue
}

// updateStatus updates and saves the current status state. It also updates some statuses before saving.
func (r *MulticlusterRoleAssignmentReconciler) updateStatus(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	r.initializeRoleAssignmentStatuses(mra)

	readyStatus, readyReason, readyMessage := r.calculateReadyCondition(mra)
	r.setCondition(mra, ConditionTypeReady, readyStatus, readyReason, readyMessage)

	return r.Status().Update(ctx, mra)
}

// initializeRoleAssignmentStatuses initializes status entries for all new role assignments in the spec.
func (r *MulticlusterRoleAssignmentReconciler) initializeRoleAssignmentStatuses(
	mra *rbacv1alpha1.MulticlusterRoleAssignment) {
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		// Only initialize if status doesn't exist
		found := false
		for _, status := range mra.Status.RoleAssignments {
			if status.Name == roleAssignment.Name {
				found = true
				break
			}
		}
		if !found {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonInitializing, MessageInitializingRoleAssignment)
		}
	}
}

// setRoleAssignmentStatus sets a specific role assignment status.
func (r *MulticlusterRoleAssignmentReconciler) setRoleAssignmentStatus(mra *rbacv1alpha1.MulticlusterRoleAssignment,
	name, state, reason, message string) {
	found := false
	for i, roleAssignmentStatus := range mra.Status.RoleAssignments {
		if roleAssignmentStatus.Name == name {
			mra.Status.RoleAssignments[i].Status = state
			mra.Status.RoleAssignments[i].Reason = reason
			mra.Status.RoleAssignments[i].Message = message
			found = true
			break
		}
	}
	if !found {
		mra.Status.RoleAssignments = append(mra.Status.RoleAssignments, rbacv1alpha1.RoleAssignmentStatus{
			Name:    name,
			Status:  state,
			Reason:  reason,
			Message: message,
		})
	}
}

// calculateReadyCondition determines the Ready condition based on other conditions and role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) calculateReadyCondition(mra *rbacv1alpha1.MulticlusterRoleAssignment) (
	metav1.ConditionStatus, string, string) {
	var validatedCondition *metav1.Condition

	for _, condition := range mra.Status.Conditions {
		if condition.Type == ConditionTypeValidated {
			validatedCondition = &condition
		}
	}

	if validatedCondition != nil && validatedCondition.Status == metav1.ConditionFalse {
		return metav1.ConditionFalse, ReasonInvalidSpec, MessageSpecValidationFailed
	}

	var errorCount, activeCount, pendingCount int

	for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
		switch roleAssignmentStatus.Status {
		case StatusTypeError:
			errorCount++
		case StatusTypeActive:
			activeCount++
		case StatusTypePending:
			pendingCount++
		}
	}

	if errorCount > 0 {
		return metav1.ConditionFalse, ReasonPartialFailure, fmt.Sprintf("%d out of %d %s", errorCount,
			len(mra.Status.RoleAssignments), MessageRoleAssignmentsFailed)
	}

	if pendingCount > 0 {
		return metav1.ConditionFalse, ReasonInProgress, fmt.Sprintf("%d out of %d %s", pendingCount,
			len(mra.Status.RoleAssignments), MessageRoleAssignmentsPending)
	}

	if activeCount == len(mra.Status.RoleAssignments) && len(mra.Status.RoleAssignments) > 0 {
		return metav1.ConditionTrue, ReasonAllApplied, fmt.Sprintf("%d out of %d %s", activeCount,
			len(mra.Status.RoleAssignments), MessageRoleAssignmentsAppliedSuccessfully)
	}

	return metav1.ConditionUnknown, ReasonUnknown, MessageStatusCannotBeDetermined
}

// setCondition sets a condition in the MulticlusterRoleAssignment status.
func (r *MulticlusterRoleAssignmentReconciler) setCondition(mra *rbacv1alpha1.MulticlusterRoleAssignment,
	conditionType string, status metav1.ConditionStatus, reason, message string) {
	condition := metav1.Condition{
		Type:               conditionType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: mra.Generation,
	}

	found := false
	for i, existingCondition := range mra.Status.Conditions {
		if existingCondition.Type == conditionType {
			if existingCondition.Status != status || existingCondition.Reason != reason || existingCondition.Message !=
				message {
				mra.Status.Conditions[i] = condition
			} else {
				mra.Status.Conditions[i].ObservedGeneration = mra.Generation
			}
			found = true
			break
		}
	}
	if !found {
		mra.Status.Conditions = append(mra.Status.Conditions, condition)
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *MulticlusterRoleAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1alpha1.MulticlusterRoleAssignment{}).
		Named("multiclusterroleassignment").
		Complete(r)
}
