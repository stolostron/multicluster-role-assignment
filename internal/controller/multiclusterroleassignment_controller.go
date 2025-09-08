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
	"slices"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
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
)

// Reconciliation constants
const (
	// DefaultRequeueDelay is the default delay for requeuing after transient errors
	DefaultRequeueDelay = 30 * time.Second
	// ClusterPermissionFailureRequeueDelay is the delay for requeuing after ClusterPermission failures
	// TODO: decide whether ClusterPermission failures should have higher time than default or not
	ClusterPermissionFailureRequeueDelay = 2 * time.Minute
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
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	specChanged := r.hasSpecChanged(&mra)
	if specChanged {
		log.Info("Spec change detected, clearing stale status", "generation", mra.Generation)
		r.clearStaleStatus(&mra)
	}

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
	if err := r.updateStatus(ctx, &mra); err != nil {
		log.Error(err, "Failed to update status after validation success")
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	log.Info("Successfully validated MulticlusterRoleAssignment spec", "multiclusterroleassignment", req.NamespacedName)

	allClusters, err := r.aggregateClusters(ctx, &mra)
	if err != nil {
		log.Error(err, "Failed to aggregate target clusters")

		if statusErr := r.updateStatus(ctx, &mra); statusErr != nil {
			log.Error(statusErr, "Failed to update status after cluster aggregation failure")
		}

		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	if err := r.updateStatus(ctx, &mra); err != nil {
		log.Error(err, "Failed to update status after cluster aggregation")
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	log.Info("Successfully aggregated target clusters", "multiclusterroleassignment", req.NamespacedName,
		"clusters", allClusters)

	clusterPermissionErrors := r.processClusterPermissions(ctx, &mra, allClusters)

	if err := r.updateStatus(ctx, &mra); err != nil {
		log.Error(err, "Failed to update status after ClusterPermission processing")
		return ctrl.Result{RequeueAfter: DefaultRequeueDelay}, err
	}

	if len(clusterPermissionErrors) > 0 {
		log.Error(fmt.Errorf("ClusterPermission processing failed for %d clusters", len(clusterPermissionErrors)),
			"ClusterPermission processing completed with errors", "failedClusters", len(clusterPermissionErrors),
			"totalClusters", len(allClusters))

		return ctrl.Result{RequeueAfter: ClusterPermissionFailureRequeueDelay}, nil
	}

	log.Info("Successfully processed ClusterPermissions", "multiclusterroleassignment", req.NamespacedName)

	log.Info("Successfully completed reconciliation", "multiclusterroleassignment", req.NamespacedName)

	return ctrl.Result{}, nil
}

// validateSpec performs basic validation on the MulticlusterRoleAssignment spec.
func (r *MulticlusterRoleAssignmentReconciler) validateSpec(
	mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
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
func (r *MulticlusterRoleAssignmentReconciler) aggregateClusters(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) ([]string, error) {
	log := logf.FromContext(ctx)

	allActiveClustersMap := make(map[string]bool)
	allMissingClustersMap := make(map[string]bool)
	var allClusters []string

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonAggregatingClusters,
			MessageAggregatingClusters)

		var missingClustersInRA []string

		for _, cluster := range roleAssignment.Clusters {
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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonClustersValid,
				MessageClustersValid)
		}
	}

	log.Info("All clusters checked and aggregated successfully")
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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StatusTypePending, ReasonInitializing,
				MessageInitializing)
		}
	}
}

// setRoleAssignmentStatus sets a specific role assignment status.
func (r *MulticlusterRoleAssignmentReconciler) setRoleAssignmentStatus(mra *rbacv1alpha1.MulticlusterRoleAssignment,
	name, status, reason, message string) {
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
			Name:    name,
			Status:  status,
			Reason:  reason,
			Message: message,
		})
	}
}

// calculateReadyCondition determines the Ready condition based on other conditions and role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) calculateReadyCondition(mra *rbacv1alpha1.MulticlusterRoleAssignment) (
	metav1.ConditionStatus, string, string) {
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

// processClusterPermissions processes ClusterPermissions for all target clusters.
func (r *MulticlusterRoleAssignmentReconciler) processClusterPermissions(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment, clusters []string) map[string]error {
	log := logf.FromContext(ctx)

	r.setCondition(mra, ConditionTypeApplied, metav1.ConditionUnknown, ReasonApplyInProgress, MessageApplyInProgress)

	state := &ClusterPermissionProcessingState{
		FailedClusters: make(map[string]error),
	}

	for _, cluster := range clusters {
		log.Info("Processing ClusterPermission for cluster", "cluster", cluster)

		if err := r.ensureClusterPermission(ctx, mra, cluster); err != nil {
			log.Error(err, "Failed to ensure ClusterPermission", "cluster", cluster)
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
func (r *MulticlusterRoleAssignmentReconciler) ensureClusterPermission(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment, cluster string) error {
	log := logf.FromContext(ctx)

	existingCP, err := r.getClusterPermission(ctx, cluster)
	if err != nil {
		return err
	}

	desiredSpec := r.buildClusterPermissionSpec(mra, cluster)

	if existingCP == nil {
		log.Info("Creating new ClusterPermission", "name", ClusterPermissionManagedName, "namespace", cluster)
		cp := &clusterpermissionv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ClusterPermissionManagedName,
				Namespace: cluster,
				Labels: map[string]string{
					ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
				},
			},
			Spec: desiredSpec,
		}

		if err := r.Create(ctx, cp); err != nil {
			log.Error(err, "Failed to create ClusterPermission")
			return err
		}

		log.Info("Successfully created ClusterPermission")
		return nil
	}

	log.Info("Updating existing ClusterPermission", "name", ClusterPermissionManagedName, "namespace", cluster)
	needsUpdate := !r.isClusterPermissionSpecEqual(existingCP.Spec, desiredSpec)

	if !needsUpdate {
		log.Info("ClusterPermission already up to date")
		// TODO: uncomment this when proper cluster permission comparison logic is implemented
		// return nil
	}

	existingCP.Spec = desiredSpec
	if err := r.Update(ctx, existingCP); err != nil {
		log.Error(err, "Failed to update ClusterPermission")
		return err
	}

	log.Info("Successfully updated ClusterPermission")
	return nil
}

// buildClusterPermissionSpec builds the desired ClusterPermission spec for the target MulticlusterRoleAssignment and
// cluster.
func (r *MulticlusterRoleAssignmentReconciler) buildClusterPermissionSpec(
	mra *rbacv1alpha1.MulticlusterRoleAssignment, cluster string) clusterpermissionv1alpha1.ClusterPermissionSpec {
	spec := clusterpermissionv1alpha1.ClusterPermissionSpec{}

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if !r.isRoleAssignmentTargetingCluster(roleAssignment, cluster) {
			continue
		}

		// TODO: change/shorten/improve name
		bindingName := fmt.Sprintf("mra-%s-%s-%s", mra.Namespace, mra.Name, roleAssignment.Name)

		if len(roleAssignment.TargetNamespaces) == 0 {
			clusterRoleBinding := clusterpermissionv1alpha1.ClusterRoleBinding{
				Name: bindingName,
				RoleRef: &rbacv1.RoleRef{
					Kind:     ClusterRoleKind,
					Name:     roleAssignment.ClusterRole,
					APIGroup: rbacv1.GroupName,
				},
				Subjects: []rbacv1.Subject{mra.Spec.Subject},
			}

			if spec.ClusterRoleBindings == nil {
				spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{}
			}
			*spec.ClusterRoleBindings = append(*spec.ClusterRoleBindings, clusterRoleBinding)
		} else {
			for _, namespace := range roleAssignment.TargetNamespaces {
				roleBinding := clusterpermissionv1alpha1.RoleBinding{
					Name:      fmt.Sprintf("%s-%s", bindingName, namespace),
					Namespace: namespace,
					RoleRef: clusterpermissionv1alpha1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     roleAssignment.ClusterRole,
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{mra.Spec.Subject},
				}

				if spec.RoleBindings == nil {
					spec.RoleBindings = &[]clusterpermissionv1alpha1.RoleBinding{}
				}
				*spec.RoleBindings = append(*spec.RoleBindings, roleBinding)
			}
		}
	}

	return spec
}

// isRoleAssignmentTargetingCluster checks if a role assignment targets a specific cluster.
func (r *MulticlusterRoleAssignmentReconciler) isRoleAssignmentTargetingCluster(
	roleAssignment rbacv1alpha1.RoleAssignment, cluster string) bool {
	return slices.Contains(roleAssignment.Clusters, cluster)
}

// isClusterPermissionSpecEqual compares two ClusterPermission specs for equality.
// TODO: Implement logic to check only relevant ClusterPermission bindings for shared ClusterPermission scenario
func (r *MulticlusterRoleAssignmentReconciler) isClusterPermissionSpecEqual(
	_, _ clusterpermissionv1alpha1.ClusterPermissionSpec) bool {
	return true
}

// hasSpecChanged checks if the spec has changed since the last reconciliation.
func (r *MulticlusterRoleAssignmentReconciler) hasSpecChanged(mra *rbacv1alpha1.MulticlusterRoleAssignment) bool {
	for _, condition := range mra.Status.Conditions {
		if condition.Type == ConditionTypeReady {
			return condition.ObservedGeneration != mra.Generation
		}
	}
	return true
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

	for i := range mra.Status.RoleAssignments {
		mra.Status.RoleAssignments[i].Status = StatusTypePending
		mra.Status.RoleAssignments[i].Reason = ReasonInitializing
		mra.Status.RoleAssignments[i].Message = MessageInitializing
	}
}

// SetupWithManager sets up the controller with the Manager.
func (r *MulticlusterRoleAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1alpha1.MulticlusterRoleAssignment{}).
		Named("multiclusterroleassignment").
		Complete(r)
}
