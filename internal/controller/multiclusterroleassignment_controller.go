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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
	"github.com/stolostron/multicluster-role-assignment/internal/utils"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
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
	ReasonClusterPermissionApplied = "ClusterPermissionApplied"
	ReasonClusterPermissionFailed  = "ClusterPermissionFailed"
	ReasonApplyInProgress          = "ApplyInProgress"

	// ConditionTypeApplied Messages
	MessageClusterPermissionApplied = "ClusterPermission applied successfully"
	MessageClusterPermissionFailed  = "ClusterPermission application failed"
	MessageApplyInProgress          = "ClusterPermission application in progress"
	MessageSpecChangedReEvaluating  = "Spec changed, re-evaluating ClusterPermissions"
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
	ReasonMissingClusters     = "MissingClusters"
	ReasonAggregatingClusters = "AggregatingClusters"
	ReasonClustersValid       = "ClustersValid"

	// RoleAssignmentStatus Messages
	MessageInitializing        = "Initializing role assignment"
	MessageMissingClusters     = "Missing managed clusters"
	MessageAggregatingClusters = "Aggregating target clusters"
	MessageClustersValid       = "All managed clusters are valid"
)

// ClusterPermission management constants
const (
	ClusterPermissionManagedByLabel = "rbac.open-cluster-management.io/managed-by"
	ClusterPermissionManagedByValue = "multiclusterroleassignment-controller"
	ClusterPermissionManagedName    = "mra-managed-permissions"
	ClusterRoleKind                 = "ClusterRole"

	// Owner binding annotation for ClusterPermission binding ownership tracking
	OwnerAnnotationPrefix = "owner.rbac.open-cluster-management.io/"
)

// Reconciliation constants
const (
	// StandardRequeueDelay is the standard delay for requeuing
	StandardRequeueDelay = 100 * time.Millisecond
	// ClusterPermissionFailureRequeueDelay is the delay for requeuing after ClusterPermission failures
	ClusterPermissionFailureRequeueDelay = 30 * time.Second
	// FinalizerName is the name of the finalizer for the MulticlusterRoleAssignment
	FinalizerName = "finalizer.rbac.open-cluster-management.io/multiclusterroleassignment"
	// AllClustersAnnotation is the annotation key for the all clusters separated by semicolon
	AllClustersAnnotation = "clusters.rbac.open-cluster-management.io"
)

// TODO: Make error constants for validateSpec functions

// MulticlusterRoleAssignmentReconciler reconciles a MulticlusterRoleAssignment object.
type MulticlusterRoleAssignmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// ClusterPermissionProcessingState tracks the processing results for each cluster when ClusterPermissions are being
// applied.
type ClusterPermissionProcessingState struct {
	// Names of clusters where ClusterPermission was applied successfully
	SuccessClusters []string
	// Names and errors of clusters where ClusterPermission applications failed
	FailedClusters map[string]error
}

// ClusterPermissionBindingSlice represents a collection of bindings and annotations that can be related to a
// ClusterPermission.
type ClusterPermissionBindingSlice struct {
	ClusterRoleBindings []clusterpermissionv1alpha1.ClusterRoleBinding
	RoleBindings        []clusterpermissionv1alpha1.RoleBinding
	OwnerAnnotations    map[string]string
}

// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/finalizers,verbs=update
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=clusterpermissions,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=managedclusters,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MulticlusterRoleAssignmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	log.Info("Starting reconciliation", "multiclusterroleassignment", req.NamespacedName)

	var mra rbacv1alpha1.MulticlusterRoleAssignment
	if err := r.Get(ctx, req.NamespacedName, &mra); err != nil {
		if apierrors.IsNotFound(err) {
			log.Info("MulticlusterRoleAssignment resource not found, skipping reconciliation")
			return ctrl.Result{}, nil
		}
		log.Error(err, "Failed to get MulticlusterRoleAssignment")
		return ctrl.Result{}, err
	}

	if mra.DeletionTimestamp.IsZero() {
		// Add finalizer for create/update
		if !controllerutil.ContainsFinalizer(&mra, FinalizerName) {
			result := controllerutil.AddFinalizer(&mra, FinalizerName)
			log.Info("Add finalizer and requeue", "finalizer", FinalizerName, "result", result)
			if err := r.Update(ctx, &mra); err != nil {
				if apierrors.IsConflict(err) {
					log.Info("Finalizer add conflict, requeuing", "generation", mra.Generation, "resourceVersion",
						mra.ResourceVersion)
					return ctrl.Result{RequeueAfter: StandardRequeueDelay}, nil
				}
				log.Error(err, "Failed to update MulticlusterRoleAssignment with finalizer")
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: StandardRequeueDelay}, nil
		}
	} else {
		// Remove finalizer for delete
		if controllerutil.ContainsFinalizer(&mra, FinalizerName) {
			if err := r.handleMulticlusterRoleAssignmentDeletion(ctx, &mra); err != nil {
				log.Error(err, "Failed to clean up resources during MulticlusterRoleAssignment deletion")
				return ctrl.Result{}, err
			}

			result := controllerutil.RemoveFinalizer(&mra, FinalizerName)
			log.Info("Remove finalizer ", "finalizer", FinalizerName, "result", result)
			if err := r.Update(ctx, &mra); err != nil {
				if apierrors.IsConflict(err) {
					log.Info("Finalizer remove conflict, requeuing", "generation", mra.Generation, "resourceVersion",
						mra.ResourceVersion)
					return ctrl.Result{RequeueAfter: StandardRequeueDelay}, nil
				}
				log.Error(err, "Failed to update MulticlusterRoleAssignment with finalizer")
				return ctrl.Result{}, err
			} else {
				log.Info("Successfully removed finalizer ", "finalizer", FinalizerName)
				return ctrl.Result{}, nil
			}
		}
	}

	if r.isFullyProcessed(&mra) {
		log.Info("All conditions current for generation, skipping reconcile", "generation", mra.Generation)
		return ctrl.Result{}, nil
	}

	r.clearStaleStatus(&mra)

	if err := r.validateSpec(&mra); err != nil {
		log.Error(err, "MulticlusterRoleAssignment spec validation failed")

		r.setCondition(&mra, ConditionTypeValidated, metav1.ConditionFalse, ReasonInvalidSpec, fmt.Sprintf("%s: %s",
			MessageSpecValidationFailed, err.Error()))
		if statusErr := r.updateStatus(ctx, &mra); statusErr != nil {
			log.Error(statusErr, "Failed to update status after validation failure")
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, err
	}

	r.setCondition(&mra, ConditionTypeValidated, metav1.ConditionTrue, ReasonSpecIsValid, MessageSpecValidationPassed)

	log.Info("Successfully validated MulticlusterRoleAssignment spec", "multiclusterroleassignment", req.NamespacedName,
		"generation", mra.Generation, "resourceVersion", mra.ResourceVersion)

	allClustersFromSpec, err := r.aggregateClusters(ctx, &mra)
	if err != nil {
		log.Error(err, "Failed to aggregate target clusters")

		if statusErr := r.updateStatus(ctx, &mra); statusErr != nil {
			log.Error(statusErr, "Failed to update status after cluster aggregation failure")
		}

		return ctrl.Result{}, err
	}

	// Add missing clusters to allClusters
	previousClusters := []string{}
	if mra.Annotations != nil && mra.Annotations[AllClustersAnnotation] != "" {
		previousClusters = strings.Split(mra.Annotations[AllClustersAnnotation], ";")
	}

	allClustersTotal := allClustersFromSpec

	missingClusters := utils.FindDifference(previousClusters, allClustersFromSpec)
	allClustersTotal = append(allClustersTotal, missingClusters...)

	log.Info("Successfully aggregated target clusters", "multiclusterroleassignment", req.NamespacedName, "clusters",
		allClustersFromSpec, "generation", mra.Generation)

	clusterPermissionErrors := r.processClusterPermissions(ctx, &mra, allClustersTotal)

	if err := r.updateAllClustersAnnotation(ctx, &mra, allClustersFromSpec); err != nil {
		if apierrors.IsConflict(err) {
			log.Info("Annotation update conflict, requeuing", "resourceVersion", mra.ResourceVersion)
			return ctrl.Result{RequeueAfter: StandardRequeueDelay}, nil
		}
		log.Error(err, "Failed to update all clusters annotation")
		return ctrl.Result{}, err
	}

	if err := r.updateStatus(ctx, &mra); err != nil {
		if apierrors.IsConflict(err) {
			log.Info("Status update conflict, requeuing", "resourceVersion", mra.ResourceVersion)
			return ctrl.Result{RequeueAfter: StandardRequeueDelay}, nil
		}
		log.Error(err, "Failed to update status after reconciliation")
		return ctrl.Result{}, err
	}

	if len(clusterPermissionErrors) > 0 {
		log.Error(fmt.Errorf("ClusterPermission processing failed for %d clusters", len(clusterPermissionErrors)),
			"ClusterPermission processing completed with errors", "failedClusters", len(clusterPermissionErrors),
			"totalClusters", len(allClustersFromSpec))

		return ctrl.Result{RequeueAfter: ClusterPermissionFailureRequeueDelay}, nil
	}

	log.Info("Successfully completed reconciliation", "multiclusterroleassignment", req.NamespacedName, "generation",
		mra.Generation, "resourceVersion", mra.ResourceVersion)

	return ctrl.Result{}, nil
}

// validateSpec performs basic validation on the MulticlusterRoleAssignment spec.
func (r *MulticlusterRoleAssignmentReconciler) validateSpec(mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	// Check for duplicate RoleAssignment names (they are not valid and should be blocked by validating webhook)
	namesMap := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if namesMap[roleAssignment.Name] {
			return fmt.Errorf("duplicate role assignment name found: %s", roleAssignment.Name)
		}
		namesMap[roleAssignment.Name] = true
	}

	return nil
}

// aggregateClusters aggregates all cluster names from RoleAssignment specs and returns a deduplicated list of cluster
// names. Validates clusters exist and updates role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) aggregateClusters(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment) ([]string, error) {

	log := logf.FromContext(ctx)

	allActiveClustersMap := make(map[string]bool)
	allMissingClustersMap := make(map[string]bool)
	var allClusters []string

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		// Only set to aggregating status if not already in error state
		var existingStatus *rbacv1alpha1.RoleAssignmentStatus
		for i, status := range mra.Status.RoleAssignments {
			if status.Name == roleAssignment.Name {
				existingStatus = &mra.Status.RoleAssignments[i]
				break
			}
		}

		// Don't overwrite error statuses, and only update if not already in a stable active state
		if existingStatus == nil || (existingStatus.Status != StatusTypeError && existingStatus.Status != StatusTypeActive) {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonAggregatingClusters,
				MessageAggregatingClusters)
		}

		var missingClustersInRA []string

		for _, cluster := range roleAssignment.ClusterSelection.ClusterNames {
			if allActiveClustersMap[cluster] {
				continue
			} else if allMissingClustersMap[cluster] {
				missingClustersInRA = append(missingClustersInRA, cluster)
				continue
			}

			var managedCluster clusterv1.ManagedCluster
			err := r.Get(ctx, client.ObjectKey{Name: cluster}, &managedCluster)
			if err != nil {
				if apierrors.IsNotFound(err) {
					log.Error(err, "Referenced ManagedCluster not found", "cluster", cluster, "roleAssignment",
						roleAssignment.Name)
					missingClustersInRA = append(missingClustersInRA, cluster)
					allMissingClustersMap[cluster] = true
				} else {
					log.Error(err, "Failed to get ManagedCluster", "cluster", cluster, "roleAssignment",
						roleAssignment.Name)
					return nil, fmt.Errorf("failed to validate cluster %s: %w", cluster, err)
				}
			} else {
				log.Info("ManagedCluster found and validated", "cluster", cluster)
				allActiveClustersMap[cluster] = true
				allClusters = append(allClusters, cluster)
			}
		}

		if len(missingClustersInRA) > 0 {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypeError, ReasonMissingClusters,
				fmt.Sprintf("%s: %v", MessageMissingClusters, missingClustersInRA))
		} else {
			// Only update to pending if not already active - preserve active status if clusters are still valid
			if existingStatus == nil || existingStatus.Status != StatusTypeActive {
				r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonClustersValid,
					MessageClustersValid)
			}
		}
	}

	return allClusters, nil
}

// getClusterPermission fetches the managed ClusterPermission for a specific cluster namespace. Returns nil if not
// found or if it doesn't have the management label.
func (r *MulticlusterRoleAssignmentReconciler) getClusterPermission(
	ctx context.Context, clusterNamespace string) (*clusterpermissionv1alpha1.ClusterPermission, error) {

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

// updateStatus calculates and saves the current status state.
func (r *MulticlusterRoleAssignmentReconciler) updateStatus(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment) error {

	r.initializeRoleAssignmentStatuses(mra)

	readyStatus, readyReason, readyMessage := r.calculateReadyCondition(mra)
	r.setCondition(mra, ConditionTypeReady, readyStatus, readyReason, readyMessage)

	err := r.Status().Update(ctx, mra)
	if err != nil {
		return err
	}

	return nil
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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonInitializing,
				MessageInitializing)
		}
	}
}

// setRoleAssignmentStatus sets a specific role assignment status.
func (r *MulticlusterRoleAssignmentReconciler) setRoleAssignmentStatus(
	mra *rbacv1alpha1.MulticlusterRoleAssignment, name, status, reason, message string) {

	found := false
	for i, roleAssignmentStatus := range mra.Status.RoleAssignments {
		if roleAssignmentStatus.Name == name {
			mra.Status.RoleAssignments[i].Status = status
			mra.Status.RoleAssignments[i].Reason = reason
			mra.Status.RoleAssignments[i].Message = message
			found = true
			break
		}
	}
	if !found {
		mra.Status.RoleAssignments = append(mra.Status.RoleAssignments, rbacv1alpha1.RoleAssignmentStatus{
			Name:      name,
			Status:    status,
			Reason:    reason,
			Message:   message,
			CreatedAt: metav1.Now(),
		})
	}
}

// isFullyProcessed checks if all conditions are current for the current generation.
func (r *MulticlusterRoleAssignmentReconciler) isFullyProcessed(mra *rbacv1alpha1.MulticlusterRoleAssignment) bool {
	expectedConditions := []string{ConditionTypeValidated, ConditionTypeApplied, ConditionTypeReady}

	for _, expectedType := range expectedConditions {
		found := false
		for _, condition := range mra.Status.Conditions {
			if condition.Type == expectedType && condition.ObservedGeneration == mra.Generation {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// calculateReadyCondition determines the Ready condition based on other conditions and role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) calculateReadyCondition(
	mra *rbacv1alpha1.MulticlusterRoleAssignment) (metav1.ConditionStatus, string, string) {

	var validatedCondition, appliedCondition *metav1.Condition

	for _, condition := range mra.Status.Conditions {
		if condition.Type == ConditionTypeValidated {
			validatedCondition = &condition
		}
		if condition.Type == ConditionTypeApplied {
			appliedCondition = &condition
		}
	}

	if validatedCondition != nil && validatedCondition.Status == metav1.ConditionFalse {
		return metav1.ConditionFalse, ReasonInvalidSpec, MessageSpecValidationFailed
	}

	if appliedCondition != nil && appliedCondition.Status == metav1.ConditionFalse {
		return metav1.ConditionFalse, ReasonApplyFailed, MessageClusterPermissionFailed
	}

	var errorCount, activeCount, pendingCount int
	totalRoleAssignments := len(mra.Status.RoleAssignments)

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
			totalRoleAssignments, MessageRoleAssignmentsFailed)
	}

	if pendingCount > 0 {
		return metav1.ConditionFalse, ReasonInProgress, fmt.Sprintf("%d out of %d %s", pendingCount,
			totalRoleAssignments, MessageRoleAssignmentsPending)
	}

	if activeCount == totalRoleAssignments && totalRoleAssignments > 0 {
		return metav1.ConditionTrue, ReasonAllApplied, fmt.Sprintf("%d out of %d %s", activeCount, totalRoleAssignments,
			MessageRoleAssignmentsAppliedSuccessfully)
	}

	return metav1.ConditionUnknown, ReasonUnknown, MessageStatusCannotBeDetermined
}

// setCondition sets a condition in the MulticlusterRoleAssignment status.
func (r *MulticlusterRoleAssignmentReconciler) setCondition(
	mra *rbacv1alpha1.MulticlusterRoleAssignment, conditionType string,
	status metav1.ConditionStatus, reason, message string) {

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

// processClusterPermissions processes ClusterPermissions for all target clusters.
func (r *MulticlusterRoleAssignmentReconciler) processClusterPermissions(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment, clusters []string) map[string]error {

	log := logf.FromContext(ctx)

	r.setCondition(mra, ConditionTypeApplied, metav1.ConditionUnknown, ReasonApplyInProgress, MessageApplyInProgress)

	state := &ClusterPermissionProcessingState{
		FailedClusters: make(map[string]error),
	}

	for _, cluster := range clusters {
		log.Info("Processing ClusterPermission for cluster", "cluster", cluster)

		if err := r.ensureClusterPermission(ctx, mra, cluster); err != nil {
			state.FailedClusters[cluster] = err
		} else {
			state.SuccessClusters = append(state.SuccessClusters, cluster)
		}
	}

	r.updateRoleAssignmentStatuses(mra, clusters, state)

	successCount := len(state.SuccessClusters)
	totalClusters := len(clusters)

	if successCount == totalClusters {
		r.setCondition(mra, ConditionTypeApplied, metav1.ConditionTrue, ReasonClusterPermissionApplied,
			MessageClusterPermissionApplied)
	} else {
		r.setCondition(mra, ConditionTypeApplied, metav1.ConditionFalse, ReasonClusterPermissionFailed,
			fmt.Sprintf("%s to %d out of %d clusters", MessageClusterPermissionFailed, totalClusters-successCount,
				totalClusters))
	}

	return state.FailedClusters
}

// updateRoleAssignmentStatuses updates role assignment statuses based on the final ClusterPermission processing state
func (r *MulticlusterRoleAssignmentReconciler) updateRoleAssignmentStatuses(
	mra *rbacv1alpha1.MulticlusterRoleAssignment, clusters []string, state *ClusterPermissionProcessingState) {

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		// Check if role assignment already has an error status, like from the previous cluster validation stage. If
		// error status exists, we skip updating that role assignment status.
		var existingStatus *rbacv1alpha1.RoleAssignmentStatus
		for i, status := range mra.Status.RoleAssignments {
			if status.Name == roleAssignment.Name {
				existingStatus = &mra.Status.RoleAssignments[i]
				break
			}
		}

		if existingStatus != nil && existingStatus.Status == StatusTypeError {
			continue
		}

		var failedClustersForRA []string
		var successClustersForRA []string

		for _, cluster := range clusters {
			if r.isRoleAssignmentTargetingCluster(roleAssignment, cluster) {
				if _, failed := state.FailedClusters[cluster]; failed {
					failedClustersForRA = append(failedClustersForRA, cluster)
				} else {
					successClustersForRA = append(successClustersForRA, cluster)
				}
			}
		}

		if len(failedClustersForRA) > 0 {
			var errorParts []string
			for _, cluster := range failedClustersForRA {
				err := state.FailedClusters[cluster]
				errorParts = append(errorParts, fmt.Sprintf("%s for cluster %s: %v", MessageClusterPermissionFailed,
					cluster, err))
			}
			finalMessage := fmt.Sprintf("Failed on %d/%d clusters: %s", len(failedClustersForRA),
				len(failedClustersForRA)+len(successClustersForRA), strings.Join(errorParts, "; "))

			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypeError, ReasonClusterPermissionFailed,
				finalMessage)
		} else if len(successClustersForRA) > 0 {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypeActive, ReasonClusterPermissionApplied,
				MessageClusterPermissionApplied)
		}
	}
}

// ensureClusterPermission creates or updates the ClusterPermission for a specific cluster.
func (r *MulticlusterRoleAssignmentReconciler) ensureClusterPermission(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment, cluster string) error {

	log := logf.FromContext(ctx)

	// Retry logic for optimistic concurrency conflicts
	for retryCount := range 3 {
		if retryCount > 0 {
			log.Info("Retrying ClusterPermission operation", "cluster", cluster, "attempt", retryCount+1)
		}

		err := r.ensureClusterPermissionAttempt(ctx, mra, cluster)
		if err == nil {
			return nil
		}

		if apierrors.IsConflict(err) {
			if retryCount < 2 {
				log.Info("ClusterPermission conflict detected, will retry", "cluster", cluster)
				continue
			}

			log.Error(err, "ClusterPermission update failed after all retry attempts", "cluster", cluster, "attempts", 3)
			return fmt.Errorf("failed after 3 attempts due to conflicts: %w", err)
		}

		log.Error(err, "ClusterPermission operation failed", "cluster", cluster, "attempt", retryCount+1)
		return err
	}

	return fmt.Errorf("unexpected retry loop exit")
}

// ensureClusterPermissionAttempt performs a single attempt to create or update a ClusterPermission.
func (r *MulticlusterRoleAssignmentReconciler) ensureClusterPermissionAttempt(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment, cluster string) error {

	log := logf.FromContext(ctx)

	existingCP, err := r.getClusterPermission(ctx, cluster)
	if err != nil {
		return err
	}

	// desiredSliceCP are the bindings and annotations for the ClusterPermission related to THIS cluster derived from
	// the MulticlusterRoleAssignment
	desiredSliceCP := r.calculateDesiredClusterPermissionSlice(mra, cluster)

	if existingCP == nil {
		log.Info("Creating new ClusterPermission", "name", ClusterPermissionManagedName, "namespace", cluster)

		// Merging empty bindings for "others" because this is a new ClusterPermission
		newSpec := r.mergeClusterPermissionSpecs(ClusterPermissionBindingSlice{}, desiredSliceCP)
		newAnnotations := r.mergeClusterPermissionAnnotations(ClusterPermissionBindingSlice{}, desiredSliceCP)

		cp := &clusterpermissionv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ClusterPermissionManagedName,
				Namespace: cluster,
				Labels: map[string]string{
					ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
				},
				Annotations: newAnnotations,
			},
			Spec: newSpec,
		}

		if err := r.Create(ctx, cp); err != nil {
			return err
		}

		log.Info("Successfully created ClusterPermission")
		return nil
	}

	log.Info("Updating existing ClusterPermission", "name", ClusterPermissionManagedName, "namespace", cluster)

	// otherSliceCP are the bindings and annotations for the given ClusterPermission that come from OTHER
	// MulticlusterRoleAssignments. In other words, these are pre-existing bindings and annotations on the
	// ClusterPermission that are not managed by this MulticlusterRoleAssignment.
	otherSliceCP := r.extractOthersClusterPermissionSlice(existingCP, mra)

	newSpec := r.mergeClusterPermissionSpecs(otherSliceCP, desiredSliceCP)
	newAnnotations := r.mergeClusterPermissionAnnotations(otherSliceCP, desiredSliceCP)

	updatedCP := existingCP
	updatedCP.Spec = newSpec
	updatedCP.Annotations = newAnnotations

	// Check if we update or delete the ClusterPermission
	if (newSpec.ClusterRoleBindings == nil || len(*newSpec.ClusterRoleBindings) == 0) &&
		(newSpec.RoleBindings == nil || len(*newSpec.RoleBindings) == 0) {
		log.Info("Deleting ClusterPermission", "clusterPermission", updatedCP.Name)
		if err := r.Delete(ctx, updatedCP); err != nil {
			return err
		}
	} else {
		if err := r.Update(ctx, updatedCP); err != nil {
			return err
		}
	}

	log.Info("Successfully updated ClusterPermission")
	return nil
}

// isRoleAssignmentTargetingCluster checks if a role assignment targets a specific cluster.
func (r *MulticlusterRoleAssignmentReconciler) isRoleAssignmentTargetingCluster(
	roleAssignment rbacv1alpha1.RoleAssignment, cluster string) bool {

	return slices.Contains(roleAssignment.ClusterSelection.ClusterNames, cluster)
}

// clearStaleStatus clears status information that may be stale due to spec changes.
func (r *MulticlusterRoleAssignmentReconciler) clearStaleStatus(mra *rbacv1alpha1.MulticlusterRoleAssignment) {
	for i, condition := range mra.Status.Conditions {
		if condition.Type == ConditionTypeApplied {
			mra.Status.Conditions[i].Status = metav1.ConditionUnknown
			mra.Status.Conditions[i].Reason = ReasonApplyInProgress
			mra.Status.Conditions[i].Message = MessageSpecChangedReEvaluating
			mra.Status.Conditions[i].LastTransitionTime = metav1.Now()
			mra.Status.Conditions[i].ObservedGeneration = mra.Generation
			break
		}
	}

	currentRoleAssignmentNames := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		currentRoleAssignmentNames[roleAssignment.Name] = true
	}

	var currentRoleAssignmentStatuses []rbacv1alpha1.RoleAssignmentStatus
	for _, status := range mra.Status.RoleAssignments {
		if currentRoleAssignmentNames[status.Name] {
			status.Status = StatusTypePending
			status.Reason = ReasonInitializing
			status.Message = MessageInitializing
			currentRoleAssignmentStatuses = append(currentRoleAssignmentStatuses, status)
		}
	}
	mra.Status.RoleAssignments = currentRoleAssignmentStatuses
}

// generateBindingName creates a deterministic and unique binding name using all key binding properties. This ensures
// different bindings get different names even when they share some properties. Binding name must be unique or else
// ClusterPermission may fail to apply it.
func (r *MulticlusterRoleAssignmentReconciler) generateBindingName(mra *rbacv1alpha1.MulticlusterRoleAssignment,
	roleAssignmentName, roleName string, bindingNamespace ...string) string {

	var data []byte
	data = fmt.Appendf(data, "%s/%s/%s/%s/%s/%s",
		mra.Namespace,
		mra.Name,
		mra.Spec.Subject.Kind,
		mra.Spec.Subject.Name,
		roleAssignmentName,
		roleName)

	if len(bindingNamespace) > 0 && bindingNamespace[0] != "" {
		data = fmt.Appendf(data, "/%s", bindingNamespace[0])
	}

	h := sha256.Sum256(data)
	hash := hex.EncodeToString(h[:])[:16]

	invalidCharsRegex := regexp.MustCompile(`[^a-z0-9-.]`)
	sanitizedRoleName := strings.ToLower(roleName)
	sanitizedRoleName = invalidCharsRegex.ReplaceAllString(sanitizedRoleName, "-")
	sanitizedRoleName = strings.Trim(sanitizedRoleName, "-")

	// Ensure we do not go over the 63 character kubernetes annotation key name limit
	maxRoleNameLength := 46
	if len(sanitizedRoleName) > maxRoleNameLength {
		sanitizedRoleName = sanitizedRoleName[:maxRoleNameLength]
	}

	return sanitizedRoleName + "-" + hash
}

// generateOwnerAnnotationKey creates the ClusterPermission annotation key for tracking binding ownership in
// annotations.
func (r *MulticlusterRoleAssignmentReconciler) generateOwnerAnnotationKey(bindingName string) string {
	return OwnerAnnotationPrefix + bindingName
}

// generateMulticlusterRoleAssignmentIdentifier creates the MulticlusterRoleAssignment identifier stored as annotation
// value in the ClusterPermission owner binding annotation.
func (r *MulticlusterRoleAssignmentReconciler) generateMulticlusterRoleAssignmentIdentifier(
	mra *rbacv1alpha1.MulticlusterRoleAssignment) string {

	return fmt.Sprintf("%s/%s", mra.Namespace, mra.Name)
}

// extractOwnedBindingNames returns the list of ClusterPermission binding names owned by this MulticlusterRoleAssignment
// according to the current owner binding annotations.
func (r *MulticlusterRoleAssignmentReconciler) extractOwnedBindingNames(
	cp *clusterpermissionv1alpha1.ClusterPermission, mra *rbacv1alpha1.MulticlusterRoleAssignment) []string {

	if cp.Annotations == nil {
		return nil
	}

	targetMRAIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)
	var ownedBindings []string

	for key, value := range cp.Annotations {
		if bindingName, found := strings.CutPrefix(key, OwnerAnnotationPrefix); found && value == targetMRAIdentifier {
			ownedBindings = append(ownedBindings, bindingName)
		}
	}

	return ownedBindings
}

// calculateDesiredClusterPermissionSlice computes the desired bindings and annotations that this
// MulticlusterRoleAssignment should contribute to the ClusterPermission for this cluster.
func (r *MulticlusterRoleAssignmentReconciler) calculateDesiredClusterPermissionSlice(
	mra *rbacv1alpha1.MulticlusterRoleAssignment, cluster string) ClusterPermissionBindingSlice {

	desiredSlice := ClusterPermissionBindingSlice{
		OwnerAnnotations: make(map[string]string),
	}

	mraIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if !r.isRoleAssignmentTargetingCluster(roleAssignment, cluster) {
			continue
		}

		if len(roleAssignment.TargetNamespaces) == 0 {
			bindingName := r.generateBindingName(mra, roleAssignment.Name, roleAssignment.ClusterRole)
			ownerKey := r.generateOwnerAnnotationKey(bindingName)
			desiredSlice.OwnerAnnotations[ownerKey] = mraIdentifier

			clusterRoleBinding := clusterpermissionv1alpha1.ClusterRoleBinding{
				Name: bindingName,
				RoleRef: &rbacv1.RoleRef{
					Kind:     ClusterRoleKind,
					Name:     roleAssignment.ClusterRole,
					APIGroup: rbacv1.GroupName,
				},
				Subjects: []rbacv1.Subject{mra.Spec.Subject},
			}
			desiredSlice.ClusterRoleBindings = append(desiredSlice.ClusterRoleBindings, clusterRoleBinding)
		} else {
			for _, namespace := range roleAssignment.TargetNamespaces {
				bindingName := r.generateBindingName(mra, roleAssignment.Name, roleAssignment.ClusterRole, namespace)
				namespacedOwnerKey := r.generateOwnerAnnotationKey(bindingName)
				desiredSlice.OwnerAnnotations[namespacedOwnerKey] = mraIdentifier

				roleBinding := clusterpermissionv1alpha1.RoleBinding{
					Name:      bindingName,
					Namespace: namespace,
					RoleRef: clusterpermissionv1alpha1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     roleAssignment.ClusterRole,
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{mra.Spec.Subject},
				}
				desiredSlice.RoleBindings = append(desiredSlice.RoleBindings, roleBinding)
			}
		}
	}

	return desiredSlice
}

// extractOthersClusterPermissionSlice extracts all bindings and annotations NOT owned by this
// MulticlusterRoleAssignment from this ClusterPermission. This represents the "others" part that should be preserved
// when updating the ClusterPermission. Orphaned bindings with no ownership annotations are excluded to keep the
// ClusterPermission clean.
func (r *MulticlusterRoleAssignmentReconciler) extractOthersClusterPermissionSlice(
	cp *clusterpermissionv1alpha1.ClusterPermission,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) ClusterPermissionBindingSlice {

	othersSlice := ClusterPermissionBindingSlice{
		OwnerAnnotations: make(map[string]string),
	}

	if cp == nil {
		return othersSlice
	}

	ownedBindingNames := r.extractOwnedBindingNames(cp, mra)
	ownedBindingNamesMap := make(map[string]bool)
	for _, name := range ownedBindingNames {
		ownedBindingNamesMap[name] = true
	}

	// allTrackedBindingNames are binding names that exist in annotations. This is used to exlude orphaned bindings that
	// don't have owner tracking annotations
	allTrackedBindingNames := make(map[string]bool)
	if cp.Annotations != nil {
		for key := range cp.Annotations {
			if bindingName, found := strings.CutPrefix(key, OwnerAnnotationPrefix); found {
				allTrackedBindingNames[bindingName] = true
			}
		}
	}

	if cp.Spec.ClusterRoleBindings != nil {
		for _, binding := range *cp.Spec.ClusterRoleBindings {
			if !ownedBindingNamesMap[binding.Name] && allTrackedBindingNames[binding.Name] {
				othersSlice.ClusterRoleBindings = append(othersSlice.ClusterRoleBindings, binding)
			}
		}
	}

	if cp.Spec.RoleBindings != nil {
		for _, binding := range *cp.Spec.RoleBindings {
			if !ownedBindingNamesMap[binding.Name] && allTrackedBindingNames[binding.Name] {
				othersSlice.RoleBindings = append(othersSlice.RoleBindings, binding)
			}
		}
	}

	if cp.Annotations != nil {
		mraIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)

		// allExistingBindingNames are binding names that exist in RoleBindings and ClusterRoleBindings. This is used to
		// exlude orphaned binding annotations that don't have an active binding.
		allExistingBindingNames := make(map[string]bool)
		if cp.Spec.ClusterRoleBindings != nil {
			for _, binding := range *cp.Spec.ClusterRoleBindings {
				allExistingBindingNames[binding.Name] = true
			}
		}
		if cp.Spec.RoleBindings != nil {
			for _, binding := range *cp.Spec.RoleBindings {
				allExistingBindingNames[binding.Name] = true
			}
		}

		for key, value := range cp.Annotations {
			if !strings.HasPrefix(key, OwnerAnnotationPrefix) {
				othersSlice.OwnerAnnotations[key] = value
			} else if value != mraIdentifier {
				if bindingName, found := strings.CutPrefix(key, OwnerAnnotationPrefix); found {
					if allExistingBindingNames[bindingName] {
						othersSlice.OwnerAnnotations[key] = value
					}
				}
			}
		}
	}

	return othersSlice
}

// mergeClusterPermissionSpecs combines the "others" slice (bindings from other MulticlusterRoleAssignments) with the
// "desired" slice (this MulticlusterRoleAssignment's bindings) to create the complete desired spec for the
// ClusterPermission.
func (r *MulticlusterRoleAssignmentReconciler) mergeClusterPermissionSpecs(
	others, desired ClusterPermissionBindingSlice) clusterpermissionv1alpha1.ClusterPermissionSpec {

	cpSpec := clusterpermissionv1alpha1.ClusterPermissionSpec{}

	allClusterRoleBindings := append(others.ClusterRoleBindings, desired.ClusterRoleBindings...)

	if len(allClusterRoleBindings) > 0 {
		cpSpec.ClusterRoleBindings = &allClusterRoleBindings
	}

	allRoleBindings := append(others.RoleBindings, desired.RoleBindings...)

	if len(allRoleBindings) > 0 {
		cpSpec.RoleBindings = &allRoleBindings
	}

	return cpSpec
}

// mergeClusterPermissionAnnotations combines the "others" annotations with the "desired" annotations to create all
// owner binding annotations for the ClusterPermission.
func (r *MulticlusterRoleAssignmentReconciler) mergeClusterPermissionAnnotations(
	others, desired ClusterPermissionBindingSlice) map[string]string {

	cpAnnotations := make(map[string]string)

	maps.Copy(cpAnnotations, others.OwnerAnnotations)
	maps.Copy(cpAnnotations, desired.OwnerAnnotations)

	return cpAnnotations
}

func (r *MulticlusterRoleAssignmentReconciler) handleMulticlusterRoleAssignmentDeletion(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	log := logf.FromContext(ctx)

	log.Info("Handling MulticlusterRoleAssignment deletion")

	allClustersInSpec, err := r.aggregateClusters(ctx, mra)
	if err != nil {
		log.Error(err, "Failed to aggregate target clusters")
		return err
	}

	// Add clusters from annotation in case they were removed from spec before deletion
	previousClusters := []string{}
	if mra.Annotations != nil && mra.Annotations[AllClustersAnnotation] != "" {
		previousClusters = strings.Split(mra.Annotations[AllClustersAnnotation], ";")
	}

	allClustersTotal := allClustersInSpec
	missingClusters := utils.FindDifference(previousClusters, allClustersInSpec)
	allClustersTotal = append(allClustersTotal, missingClusters...)

	// Create an empty MRA copy to represent the desired state (no bindings)
	emptyMRA := mra.DeepCopy()
	emptyMRA.Spec.RoleAssignments = []rbacv1alpha1.RoleAssignment{}

	var cleanupErrors []error

	for _, cluster := range allClustersTotal {
		log.Info("Processing ClusterPermission cleanup for cluster", "cluster", cluster)

		if err := r.ensureClusterPermission(ctx, emptyMRA, cluster); err != nil {
			log.Error(err, "Failed to cleanup ClusterPermission for cluster", "cluster", cluster)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cluster %s: %w", cluster, err))
		}
	}

	if len(cleanupErrors) > 0 {
		log.Error(fmt.Errorf("cleanup failed for %d/%d clusters", len(cleanupErrors), len(allClustersTotal)),
			"MulticlusterRoleAssignment deletion completed with errors", "failedClusters", len(cleanupErrors),
			"totalClusters", len(allClustersTotal))
		return fmt.Errorf("failed to cleanup %d/%d clusters during deletion: %v",
			len(cleanupErrors), len(allClustersTotal), cleanupErrors)
	}

	log.Info("Successfully completed MulticlusterRoleAssignment deletion cleanup")
	return nil
}

func (r *MulticlusterRoleAssignmentReconciler) updateAllClustersAnnotation(
	ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment, allClusters []string) error {
	log := logf.FromContext(ctx)

	log.Info("Updating all clusters annotation", "multiclusterroleassignment", mra.Name)

	// Fetch a fresh copy to avoid overwriting in-memory status
	freshMRA := &rbacv1alpha1.MulticlusterRoleAssignment{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(mra), freshMRA); err != nil {
		return err
	}

	if freshMRA.Annotations == nil {
		freshMRA.Annotations = make(map[string]string)
	}
	freshMRA.Annotations[AllClustersAnnotation] = strings.Join(allClusters, ";")

	if err := r.Update(ctx, freshMRA); err != nil {
		return err
	}

	// Update the in-memory MRA's resourceVersion to prevent conflicts in subsequent status updates
	mra.ResourceVersion = freshMRA.ResourceVersion

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *MulticlusterRoleAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1alpha1.MulticlusterRoleAssignment{},
			builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("multiclusterroleassignment").
		Complete(r)
}
