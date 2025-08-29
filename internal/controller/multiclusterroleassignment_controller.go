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

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
)

// MulticlusterRoleAssignmentReconciler reconciles a MulticlusterRoleAssignment object.
type MulticlusterRoleAssignmentReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=rbac.open-cluster-management.io,resources=multiclusterroleassignments/finalizers,verbs=update

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
	if err := r.validateSpec(&mra); err != nil {
		log.Error(err, "MulticlusterRoleAssignment spec validation failed")

		if statusErr := r.updateValidationStatus(ctx, &mra, false, "InvalidSpec", err.Error()); statusErr != nil {
			log.Error(statusErr, "Failed to update status after validation failure")
			return ctrl.Result{}, statusErr
		}
		return ctrl.Result{}, err
	}

	if err := r.updateValidationStatus(ctx, &mra, true, "SpecIsValid", "Spec validation passed"); err != nil {
		log.Error(err, "Failed to update status after validation success")
		return ctrl.Result{}, err
	}

	log.Info("Successfully validated MulticlusterRoleAssignment spec", "multiclusterroleassignment", req.NamespacedName)
	return ctrl.Result{}, nil
}

// validateSpec performs validation on the MulticlusterRoleAssignment spec.
func (r *MulticlusterRoleAssignmentReconciler) validateSpec(mra *rbacv1alpha1.MulticlusterRoleAssignment) error {
	// Check for duplicate RoleAssignment names (they are not valid and should be blocked by validating webhook)
	namesSet := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if namesSet[roleAssignment.Name] {
			return fmt.Errorf("duplicate role assignment name found: %s", roleAssignment.Name)
		}
		namesSet[roleAssignment.Name] = true
	}

	return nil
}

// updateValidationStatus updates the Validated condition in the MulticlusterRoleAssignment status.
func (r *MulticlusterRoleAssignmentReconciler) updateValidationStatus(ctx context.Context, mra *rbacv1alpha1.MulticlusterRoleAssignment, isValid bool, reason, message string) error {
	status := metav1.ConditionFalse
	if isValid {
		status = metav1.ConditionTrue
	}

	condition := metav1.Condition{
		Type:               "Validated",
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}

	found := false
	for i, existingCondition := range mra.Status.Conditions {
		if existingCondition.Type == "Validated" {
			mra.Status.Conditions[i] = condition
			found = true
			break
		}
	}
	if !found {
		mra.Status.Conditions = append(mra.Status.Conditions, condition)
	}

	return r.Status().Update(ctx, mra)
}

// SetupWithManager sets up the controller with the Manager.
func (r *MulticlusterRoleAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&rbacv1alpha1.MulticlusterRoleAssignment{}).
		Named("multiclusterroleassignment").
		Complete(r)
}
