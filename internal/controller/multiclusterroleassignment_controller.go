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
	clusterv1beta2 "open-cluster-management.io/api/cluster/v1beta2"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// Condition types
const (
	ConditionTypeReady     = "Ready"
	ConditionTypeValidated = "Validated"
	ConditionTypeApplied   = "Applied"
)

// Condition reasons
const (
	ReasonValidationFailed           = "ValidationFailed"
	ReasonInvalidSpec                = "InvalidSpec"
	ReasonSpecIsValid                = "SpecIsValid"
	ReasonPartialFailure             = "PartialFailure"
	ReasonApplyFailed                = "ApplyFailed"
	ReasonInProgress                 = "InProgress"
	ReasonAllApplied                 = "AllApplied"
	ReasonUnknown                    = "Unknown"
	ReasonMissingClusterSets         = "MissingClusterSets"
	ReasonClusterSetValidationFailed = "ClusterSetValidationFailed"
)

// Role assignment states
const (
	StateTypePending = "Pending"
	StateTypeApplied = "Applied"
	StateTypeFailed  = "Failed"
)

// Status messages
const (
	MessageSpecValidationFailed               = "Spec validation failed"
	MessageSpecValidationPassed               = "Spec validation passed"
	MessageInitializingRoleAssignment         = "Initializing role assignment"
	MessageApplyClusterPermissionsFailed      = "Failed to apply ClusterPermissions"
	MessageStatusCannotBeDetermined           = "Status cannot be determined"
	MessageMissingManagedClusterSets          = "Missing ManagedClusterSets"
	MessageManagedClusterSetValidationPassed  = "ManagedClusterSet validation passed"
	MessageRoleAssignmentsFailed              = "role assignments failed"
	MessageRoleAssignmentsPending             = "role assignments pending"
	MessageRoleAssignmentsAppliedSuccessfully = "role assignments applied successfully"
)

//TODO: Make error constants for validateSpec functions

// MulticlusterRoleAssignmentReconciler reconciles a MulticlusterRoleAssignment object.
type MulticlusterRoleAssignmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/finalizers,verbs=update
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=managedclustersets,verbs=get;list;watch

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
		// TODO check logic, test should fail if error string contains does not matcj
		if strings.Contains(err.Error(), "missing ManagedClusterSets") {
			reason = ReasonMissingClusterSets
		}

		r.setCondition(&mra, ConditionTypeValidated, metav1.ConditionFalse, reason, err.Error())
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
	return ctrl.Result{}, nil
}

// validateSpec performs validation on the MulticlusterRoleAssignment spec.
func (r *MulticlusterRoleAssignmentReconciler) validateSpec(ctx context.Context,
	mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	// Check for duplicate RoleAssignment names (they are not valid and should be blocked by validating webhook)
	namesSet := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if namesSet[roleAssignment.Name] {
			return fmt.Errorf("duplicate role assignment name found: %s", roleAssignment.Name)
		}
		namesSet[roleAssignment.Name] = true
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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StateTypeFailed,
				fmt.Sprintf("%s: %v", MessageMissingManagedClusterSets, missingClusterSetsForRA))
		} else {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StateTypePending,
				MessageManagedClusterSetValidationPassed)
		}
	}

	if len(allMissingClusterSets) > 0 {
		return fmt.Errorf("missing ManagedClusterSets: %v", allMissingClusterSets)
	}

	return nil
}

// updateStatus performs a complete status update including all conditions and role assignment statuses.
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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, StateTypePending, MessageInitializingRoleAssignment)
		}
	}
}

// setRoleAssignmentStatus sets a specific role assignment status.
func (r *MulticlusterRoleAssignmentReconciler) setRoleAssignmentStatus(mra *rbacv1alpha1.MulticlusterRoleAssignment,
	name, state, message string) {
	found := false
	for i, roleAssignmentStatus := range mra.Status.RoleAssignments {
		if roleAssignmentStatus.Name == name {
			mra.Status.RoleAssignments[i].State = state
			mra.Status.RoleAssignments[i].Message = message
			found = true
			break
		}
	}
	if !found {
		mra.Status.RoleAssignments = append(mra.Status.RoleAssignments, rbacv1alpha1.RoleAssignmentStatus{
			Name:    name,
			State:   state,
			Message: message,
		})
	}
}

// calculateReadyCondition determines the Ready condition based on other conditions and role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) calculateReadyCondition(mra *rbacv1alpha1.MulticlusterRoleAssignment) (
	metav1.ConditionStatus, string, string) {
	var validatedCondition, appliedCondition *metav1.Condition

	for _, condition := range mra.Status.Conditions {
		switch condition.Type {
		case ConditionTypeValidated:
			validatedCondition = &condition
		case ConditionTypeApplied:
			appliedCondition = &condition
		}
	}

	if validatedCondition != nil && validatedCondition.Status == metav1.ConditionFalse {
		return metav1.ConditionFalse, ReasonValidationFailed, MessageSpecValidationFailed
	}

	var failedCount, appliedCount, pendingCount int

	for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
		switch roleAssignmentStatus.State {
		case StateTypeFailed:
			failedCount++
		case StateTypeApplied:
			appliedCount++
		case StateTypePending:
			pendingCount++
		}
	}

	if failedCount > 0 {
		return metav1.ConditionFalse, ReasonPartialFailure, fmt.Sprintf("%d out of %d %s",
			failedCount, len(mra.Status.RoleAssignments), MessageRoleAssignmentsFailed)
	}

	if appliedCondition != nil && appliedCondition.Status == metav1.ConditionFalse {
		return metav1.ConditionFalse, ReasonApplyFailed, MessageApplyClusterPermissionsFailed
	}

	if pendingCount > 0 {
		return metav1.ConditionUnknown, ReasonInProgress, fmt.Sprintf("%d %s", pendingCount,
			MessageRoleAssignmentsPending)
	}

	if appliedCount == len(mra.Status.RoleAssignments) && len(mra.Status.RoleAssignments) > 0 {
		return metav1.ConditionTrue, ReasonAllApplied, fmt.Sprintf("All %d %s",
			appliedCount, MessageRoleAssignmentsAppliedSuccessfully)
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
