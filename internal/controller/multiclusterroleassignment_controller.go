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
	"sort"
	"strings"
	"time"

	"github.com/stolostron/multicluster-role-assignment/internal/utils"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// ClusterPermission management constants.
const (
	clusterPermissionManagedByLabel = "rbac.open-cluster-management.io/managed-by"
	clusterPermissionManagedByValue = "multiclusterroleassignment-controller"
	clusterPermissionMRAOwnerAnn    = "rbac.open-cluster-management.io/mra-owner"
	clusterRoleKind                 = "ClusterRole"
	conditionTypeApplied            = "Applied"

	// Legacy constants for migration from shared ClusterPermission model.
	legacyClusterPermissionName = "mra-managed-permissions"
	legacyOwnerAnnotationPrefix = "owner/"
)

// Reconciliation constants.
const (
	standardRequeueDelay = 100 * time.Millisecond
	finalizerName        = "finalizer.rbac.open-cluster-management.io/multiclusterroleassignment"
	placementIndexField  = "spec.roleAssignments.clusterSelection.placements"
)

// deletionTimestampSetPredicate passes any update event where the object's
// DeletionTimestamp is non-zero, ensuring deletion reconciliation fires even
// when the generation has not changed (metadata-only update).
var deletionTimestampSetPredicate = predicate.NewPredicateFuncs(func(obj client.Object) bool {
	return !obj.GetDeletionTimestamp().IsZero()
})

// SetupIndexes configures field indexes for efficient lookups.
// This should be called before setting up the controller.
func SetupIndexes(ctx context.Context, mgr ctrl.Manager) error {
	// Index MRAs by the Placements they reference in their RoleAssignments
	if err := mgr.GetFieldIndexer().IndexField(
		ctx, &mrav1beta1.MulticlusterRoleAssignment{}, placementIndexField, extractPlacementKeys); err != nil {
		return fmt.Errorf("failed to setup placement index: %w", err)
	}

	return nil
}

// extractPlacementKeys extracts placement keys from an MRA for indexing.
// Returns keys in format "namespace/name" for each referenced Placement.
func extractPlacementKeys(obj client.Object) []string {
	mra, ok := obj.(*mrav1beta1.MulticlusterRoleAssignment)
	if !ok {
		return nil
	}

	// Use a map to deduplicate placement references
	placementSet := make(map[string]struct{})
	for _, ra := range mra.Spec.RoleAssignments {
		for _, p := range ra.ClusterSelection.Placements {
			key := fmt.Sprintf("%s/%s", p.Namespace, p.Name)
			placementSet[key] = struct{}{}
		}
	}

	// Convert map to slice
	placements := make([]string, 0, len(placementSet))
	for key := range placementSet {
		placements = append(placements, key)
	}

	return placements
}

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
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=placements,verbs=get;list;watch
// +kubebuilder:rbac:groups=cluster.open-cluster-management.io,resources=placementdecisions,verbs=get;list;watch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *MulticlusterRoleAssignmentReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	log.Info("Starting reconciliation", "multiclusterroleassignment", req.NamespacedName)

	var mra mrav1beta1.MulticlusterRoleAssignment
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
		if !controllerutil.ContainsFinalizer(&mra, finalizerName) {
			result := controllerutil.AddFinalizer(&mra, finalizerName)
			log.Info("Add finalizer and requeue", "finalizer", finalizerName, "result", result)
			if err := r.Update(ctx, &mra); err != nil {
				if apierrors.IsConflict(err) {
					log.Info("Finalizer add conflict, requeuing", "generation", mra.Generation, "resourceVersion",
						mra.ResourceVersion)
					return ctrl.Result{RequeueAfter: standardRequeueDelay}, nil
				}
				log.Error(err, "Failed to update MulticlusterRoleAssignment with finalizer")
				return ctrl.Result{}, err
			}
			return ctrl.Result{RequeueAfter: standardRequeueDelay}, nil
		}
	} else {
		// Remove finalizer for delete
		if controllerutil.ContainsFinalizer(&mra, finalizerName) {
			if err := r.handleMulticlusterRoleAssignmentDeletion(ctx, &mra); err != nil {
				log.Error(err, "Failed to clean up resources during MulticlusterRoleAssignment deletion")
				return ctrl.Result{}, err
			}

			result := controllerutil.RemoveFinalizer(&mra, finalizerName)
			log.Info("Removing finalizer ", "finalizer", finalizerName, "result", result)
			if err := r.Update(ctx, &mra); err != nil {
				if apierrors.IsConflict(err) {
					log.Info("Finalizer remove conflict, requeuing", "generation", mra.Generation, "resourceVersion",
						mra.ResourceVersion)
					return ctrl.Result{RequeueAfter: standardRequeueDelay}, nil
				}
				if apierrors.IsNotFound(err) {
					log.Info("MulticlusterRoleAssignment already deleted, finalizer removal not needed")
					return ctrl.Result{}, nil
				}
				log.Error(err, "Failed to update MulticlusterRoleAssignment with finalizer")
				return ctrl.Result{}, err
			}

			return ctrl.Result{}, nil
		}
	}

	if !mra.DeletionTimestamp.IsZero() && !controllerutil.ContainsFinalizer(&mra, finalizerName) {
		log.Info("MulticlusterRoleAssignment is being deleted without finalizer, skipping reconciliation")
		return ctrl.Result{}, nil
	}

	r.clearStaleStatus(&mra)

	currentClusters, roleAssignmentClusters, err := r.aggregateClusters(ctx, &mra)
	if err != nil {
		if statusErr := r.updateStatus(ctx, &mra); statusErr != nil {
			log.Error(statusErr, "Failed to update status after aggregation error")
		}

		log.Error(err, "Failed to aggregate clusters, will retry")
		return ctrl.Result{}, err
	}

	// Create clusters to process by adding previously applied clusters to ensure cleanup
	previousClusters := mra.Status.AppliedClusters
	if previousClusters == nil {
		previousClusters = []string{}
	}

	missingClusters := utils.FindDifference(previousClusters, currentClusters)
	clustersToProcess := append(append([]string{}, currentClusters...), missingClusters...)

	log.Info("Successfully aggregated target clusters", "multiclusterroleassignment", req.NamespacedName, "clusters",
		currentClusters, "generation", mra.Generation)

	clusterPermissionErrors := r.processClusterPermissions(ctx, &mra, clustersToProcess, roleAssignmentClusters)

	err = r.updateRoleAssignmentStatusesFromClusterPermission(
		ctx, &mra, roleAssignmentClusters, currentClusters)
	if err != nil {
		log.Error(err, "Failed to update role assignment statuses from ClusterPermission",
			"multiclusterroleassignment", req.NamespacedName,
			"clusters", currentClusters)
		return ctrl.Result{}, err
	}

	slices.Sort(currentClusters)
	mra.Status.AppliedClusters = currentClusters

	if err := r.updateStatus(ctx, &mra); err != nil {
		if apierrors.IsConflict(err) {
			log.Info("Status update conflict, requeuing", "resourceVersion", mra.ResourceVersion)
			return ctrl.Result{RequeueAfter: standardRequeueDelay}, nil
		}
		log.Error(err, "Failed to update status after reconciliation")
		return ctrl.Result{}, err
	}

	if len(clusterPermissionErrors) > 0 {
		log.Error(fmt.Errorf("ClusterPermission processing failed for %d clusters", len(clusterPermissionErrors)),
			"ClusterPermission processing completed with errors", "failedClusters", len(clusterPermissionErrors),
			"totalClusters", len(clustersToProcess))

		return ctrl.Result{}, fmt.Errorf("failed to process ClusterPermissions for %d/%d clusters",
			len(clusterPermissionErrors), len(clustersToProcess))
	}

	log.Info("Successfully completed reconciliation", "multiclusterroleassignment", req.NamespacedName, "generation",
		mra.Generation, "resourceVersion", mra.ResourceVersion)

	return ctrl.Result{}, nil
}

// aggregateClusters aggregates all cluster names from RoleAssignments and returns a deduplicated list of cluster names,
// a map of RoleAssignment names to their target clusters, and an error. Updates role assignment statuses based on
// results.
func (r *MulticlusterRoleAssignmentReconciler) aggregateClusters(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment) (
	allClusters []string, roleAssignmentClusters map[string][]string, err error) {

	log := logf.FromContext(ctx)

	allClustersMap := make(map[string]bool)
	roleAssignmentClusters = make(map[string][]string)

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		// Only set to aggregating status if not already in error state
		var existingStatus *mrav1beta1.RoleAssignmentStatus
		for i, status := range mra.Status.RoleAssignments {
			if status.Name == roleAssignment.Name {
				existingStatus = &mra.Status.RoleAssignments[i]
				break
			}
		}

		// Don't overwrite error statuses, and only update if not already in a stable active state
		if existingStatus == nil || (existingStatus.Status != string(mrav1beta1.StatusTypeError) &&
			existingStatus.Status != string(mrav1beta1.StatusTypeActive)) {

			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypePending,
				mrav1beta1.ReasonProcessing, "Resolving target clusters")
		}

		clustersInRA, err := r.resolveAllPlacementClusters(ctx, roleAssignment.ClusterSelection.Placements)
		if err != nil {
			log.Error(err, "Failed to resolve placement clusters", "roleAssignment", roleAssignment.Name)

			if apierrors.IsNotFound(err) {
				// Persistent error: Placement doesn't exist (user must fix this). It is safe to continue processing
				// other RoleAssignments
				r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypeError,
					mrav1beta1.ReasonInvalidReference, fmt.Sprintf("Placement not found: %v", err))
				continue
			} else {
				// Transient error: API timeout, connection error, etc. Not safe to continue (could cause incorrect
				// ClusterPermission deletions).
				return nil, nil, fmt.Errorf(
					"error resolving clusters for role assignment %s: %w", roleAssignment.Name, err)
			}
		}

		if len(clustersInRA) == 0 {
			log.Info("No clusters resolved from placements", "roleAssignment", roleAssignment.Name)
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypePending,
				mrav1beta1.ReasonNoMatchingClusters, "No clusters match Placement selectors")
			continue
		}

		roleAssignmentClusters[roleAssignment.Name] = clustersInRA

		for _, cluster := range clustersInRA {
			allClustersMap[cluster] = true
		}

		// Only update to pending if not already active - preserve active status if clusters are still valid
		if existingStatus == nil || existingStatus.Status != string(mrav1beta1.StatusTypeActive) {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypePending,
				mrav1beta1.ReasonProcessing, fmt.Sprintf("Resolved %d target clusters", len(clustersInRA)))
		}
	}

	allClusters = slices.Collect(maps.Keys(allClustersMap))
	slices.Sort(allClusters)

	return allClusters, roleAssignmentClusters, nil
}

// resolvePlacementClusters resolves a Placement reference to a list of cluster names by querying PlacementDecision
// resources.
func (r *MulticlusterRoleAssignmentReconciler) resolvePlacementClusters(
	ctx context.Context, placementRef mrav1beta1.PlacementRef) ([]string, error) {

	var placement clusterv1beta1.Placement
	err := r.Get(ctx, client.ObjectKey{
		Name:      placementRef.Name,
		Namespace: placementRef.Namespace,
	}, &placement)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("placement %s/%s not found: %w", placementRef.Namespace, placementRef.Name, err)
		}
		return nil, fmt.Errorf("failed to get placement %s/%s: %w", placementRef.Namespace, placementRef.Name, err)
	}

	labelSelector := labels.Set{clusterv1beta1.PlacementLabel: placementRef.Name}.AsSelector()

	var pdList clusterv1beta1.PlacementDecisionList
	err = r.List(
		ctx, &pdList, client.InNamespace(placementRef.Namespace), client.MatchingLabelsSelector{Selector: labelSelector})
	if err != nil {
		return nil, fmt.Errorf(
			"failed to list PlacementDecisions for placement %s/%s: %w", placementRef.Namespace, placementRef.Name, err)
	}

	clusterSet := make(map[string]bool)
	for _, pd := range pdList.Items {
		for _, decision := range pd.Status.Decisions {
			if decision.ClusterName != "" {
				clusterSet[decision.ClusterName] = true
			}
		}
	}

	clusters := slices.Collect(maps.Keys(clusterSet))
	slices.Sort(clusters)

	return clusters, nil
}

// resolveAllPlacementClusters resolves all Placement references in a RoleAssignment to a deduplicated list of cluster
// names.
func (r *MulticlusterRoleAssignmentReconciler) resolveAllPlacementClusters(
	ctx context.Context, placements []mrav1beta1.PlacementRef) ([]string, error) {

	allClustersMap := make(map[string]bool)

	for _, placementRef := range placements {
		clusters, err := r.resolvePlacementClusters(ctx, placementRef)
		if err != nil {
			return nil, err
		}

		for _, cluster := range clusters {
			allClustersMap[cluster] = true
		}
	}

	allClusters := slices.Collect(maps.Keys(allClustersMap))
	slices.Sort(allClusters)

	return allClusters, nil
}

// getClusterPermission fetches the dedicated ClusterPermission for an MRA in a specific cluster namespace.
// Returns nil if not found. Returns error if found but not managed by this controller or owned by a different MRA.
func (r *MulticlusterRoleAssignmentReconciler) getClusterPermission(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment, clusterNamespace string,
) (*cpv1alpha1.ClusterPermission, error) {

	log := logf.FromContext(ctx)
	cpName := r.generateClusterPermissionName(mra)
	mraIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)

	var clusterPermission cpv1alpha1.ClusterPermission
	err := r.Get(ctx, client.ObjectKey{
		Name:      cpName,
		Namespace: clusterNamespace,
	}, &clusterPermission)

	if err != nil {
		if apierrors.IsNotFound(err) {
			log.V(1).Info("ClusterPermission not found", "namespace", clusterNamespace, "name", cpName)
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get ClusterPermission: %w", err)
	}

	// Verify this CP is managed by our controller
	if !r.isClusterPermissionManaged(&clusterPermission) {
		err := fmt.Errorf("ClusterPermission found but not managed by this controller in namespace %s with name %s",
			clusterNamespace, cpName)
		log.Error(err, "ClusterPermission conflict detected", "namespace", clusterNamespace, "name", cpName)
		return nil, err
	}

	// Verify this CP is owned by this MRA (prevents hash collision issues)
	if clusterPermission.Annotations != nil && clusterPermission.Annotations[clusterPermissionMRAOwnerAnn] != "" &&
		clusterPermission.Annotations[clusterPermissionMRAOwnerAnn] != mraIdentifier {
		err := fmt.Errorf("ClusterPermission %s/%s exists but is owned by different MRA: %s (expected %s)",
			clusterNamespace, cpName, clusterPermission.Annotations[clusterPermissionMRAOwnerAnn], mraIdentifier)
		log.Error(err, "ClusterPermission ownership conflict detected",
			"namespace", clusterNamespace, "name", cpName,
			"actualOwner", clusterPermission.Annotations[clusterPermissionMRAOwnerAnn],
			"expectedOwner", mraIdentifier)
		return nil, err
	}

	return &clusterPermission, nil
}

// getLegacyClusterPermission fetches the legacy shared ClusterPermission for migration purposes.
// Returns nil if not found or if it doesn't have the management label.
func (r *MulticlusterRoleAssignmentReconciler) getLegacyClusterPermission(
	ctx context.Context, clusterNamespace string,
) (*cpv1alpha1.ClusterPermission, error) {

	log := logf.FromContext(ctx)

	var clusterPermission cpv1alpha1.ClusterPermission
	err := r.Get(ctx, client.ObjectKey{
		Name:      legacyClusterPermissionName,
		Namespace: clusterNamespace,
	}, &clusterPermission)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get legacy ClusterPermission: %w", err)
	}

	if !r.isClusterPermissionManaged(&clusterPermission) {
		// Not managed by us, leave it alone
		log.V(1).Info("Legacy ClusterPermission exists but is not managed by this controller",
			"namespace", clusterNamespace, "name", legacyClusterPermissionName)
		return nil, nil
	}

	return &clusterPermission, nil
}

// isClusterPermissionManaged checks if a ClusterPermission has the correct management label
func (r *MulticlusterRoleAssignmentReconciler) isClusterPermissionManaged(obj client.Object) bool {
	cpLabels := obj.GetLabels()
	if cpLabels == nil {
		return false
	}
	return cpLabels[clusterPermissionManagedByLabel] == clusterPermissionManagedByValue
}

// updateStatus initializes missing role assignment statuses, recalculates the Ready condition, and persists status to
// the API server.
func (r *MulticlusterRoleAssignmentReconciler) updateStatus(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment) error {

	r.initializeRoleAssignmentStatuses(mra)

	readyStatus, readyReason, readyMessage := r.calculateReadyCondition(mra)
	r.setCondition(mra, mrav1beta1.ConditionTypeReady, readyStatus, readyReason, readyMessage)

	err := r.Status().Update(ctx, mra)
	if err != nil {
		return err
	}

	return nil
}

// initializeRoleAssignmentStatuses initializes status entries for all new role assignments in the spec.
func (r *MulticlusterRoleAssignmentReconciler) initializeRoleAssignmentStatuses(
	mra *mrav1beta1.MulticlusterRoleAssignment) {

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
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypePending,
				mrav1beta1.ReasonProcessing, "Initializing")
		}
	}
}

// setRoleAssignmentStatus sets a specific role assignment status.
func (r *MulticlusterRoleAssignmentReconciler) setRoleAssignmentStatus(mra *mrav1beta1.MulticlusterRoleAssignment,
	name string, status mrav1beta1.RoleAssignmentStatusType, reason mrav1beta1.RoleAssignmentStatusReason,
	message string) {

	found := false
	for i, roleAssignmentStatus := range mra.Status.RoleAssignments {
		if roleAssignmentStatus.Name == name {
			mra.Status.RoleAssignments[i].Status = string(status)
			mra.Status.RoleAssignments[i].Reason = string(reason)
			mra.Status.RoleAssignments[i].Message = message
			found = true
			break
		}
	}
	if !found {
		mra.Status.RoleAssignments = append(mra.Status.RoleAssignments, mrav1beta1.RoleAssignmentStatus{
			Name:      name,
			Status:    string(status),
			Reason:    string(reason),
			Message:   message,
			CreatedAt: metav1.Now(),
		})
	}
}

// calculateReadyCondition determines the Ready condition based on role assignment statuses.
func (r *MulticlusterRoleAssignmentReconciler) calculateReadyCondition(
	mra *mrav1beta1.MulticlusterRoleAssignment) (metav1.ConditionStatus, mrav1beta1.ConditionReason, string) {

	var errorCount, activeCount, pendingCount int
	totalRoleAssignments := len(mra.Status.RoleAssignments)

	for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
		switch roleAssignmentStatus.Status {
		case string(mrav1beta1.StatusTypeError):
			errorCount++
		case string(mrav1beta1.StatusTypeActive):
			activeCount++
		case string(mrav1beta1.StatusTypePending):
			pendingCount++
		}
	}

	if errorCount > 0 && pendingCount > 0 {
		message := formatStatusMessage(errorCount, totalRoleAssignments, "role assignment(s) failed") + ", " +
			formatStatusMessage(pendingCount, totalRoleAssignments, "role assignment(s) pending")
		return metav1.ConditionFalse, mrav1beta1.ReasonAssignmentsFailure, message
	}

	if errorCount > 0 {
		return metav1.ConditionFalse, mrav1beta1.ReasonAssignmentsFailure, formatStatusMessage(
			errorCount, totalRoleAssignments, "role assignment(s) failed")
	}

	if pendingCount > 0 {
		return metav1.ConditionFalse, mrav1beta1.ReasonAssignmentsPending, formatStatusMessage(
			pendingCount, totalRoleAssignments, "role assignment(s) pending")
	}

	if activeCount == totalRoleAssignments && totalRoleAssignments > 0 {
		return metav1.ConditionTrue, mrav1beta1.ReasonAssignmentsReady, formatStatusMessage(
			activeCount, totalRoleAssignments, "role assignment(s) ready")
	}

	return metav1.ConditionUnknown, mrav1beta1.ReasonAssignmentsPending, "Status cannot be determined"
}

// formatStatusMessage creates a standardized status message with count information.
func formatStatusMessage(count, total int, message string) string {
	return fmt.Sprintf("%d out of %d %s", count, total, message)
}

// setCondition sets a condition in the MulticlusterRoleAssignment status.
func (r *MulticlusterRoleAssignmentReconciler) setCondition(mra *mrav1beta1.MulticlusterRoleAssignment,
	conditionType mrav1beta1.ConditionType, status metav1.ConditionStatus, reason mrav1beta1.ConditionReason,
	message string) {

	condition := metav1.Condition{
		Type:               string(conditionType),
		Status:             status,
		Reason:             string(reason),
		Message:            message,
		LastTransitionTime: metav1.Now(),
		ObservedGeneration: mra.Generation,
	}

	found := false
	for i, existingCondition := range mra.Status.Conditions {
		if existingCondition.Type == string(conditionType) {
			if existingCondition.Status != status || existingCondition.Reason != string(reason) ||
				existingCondition.Message != message {

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
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment, clusters []string,
	roleAssignmentClusters map[string][]string) map[string]error {

	r.setCondition(mra, mrav1beta1.ConditionTypeApplied, metav1.ConditionFalse, mrav1beta1.ReasonApplyInProgress,
		"ClusterPermission application in progress")

	state := &ClusterPermissionProcessingState{
		FailedClusters: make(map[string]error),
	}

	for _, cluster := range clusters {
		if err := r.ensureClusterPermission(ctx, mra, cluster, roleAssignmentClusters); err != nil {
			state.FailedClusters[cluster] = err
		} else {
			state.SuccessClusters = append(state.SuccessClusters, cluster)
		}
	}

	r.updateRoleAssignmentStatuses(mra, clusters, state, roleAssignmentClusters)

	successCount := len(state.SuccessClusters)
	totalClusters := len(clusters)

	if successCount == totalClusters {
		r.setCondition(mra, mrav1beta1.ConditionTypeApplied, metav1.ConditionTrue, mrav1beta1.ReasonApplied,
			formatStatusMessage(successCount, totalClusters, "ClusterPermission(s) applied successfully"))
	} else {
		r.setCondition(mra, mrav1beta1.ConditionTypeApplied, metav1.ConditionFalse, mrav1beta1.ReasonApplyFailed,
			formatStatusMessage(totalClusters-successCount, totalClusters, "ClusterPermission(s) application failed"))
	}

	return state.FailedClusters
}

// updateRoleAssignmentStatuses updates role assignment statuses based on the final ClusterPermission processing state.
func (r *MulticlusterRoleAssignmentReconciler) updateRoleAssignmentStatuses(
	mra *mrav1beta1.MulticlusterRoleAssignment, clusters []string, state *ClusterPermissionProcessingState,
	roleAssignmentClusters map[string][]string) {

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		// Check if role assignment already has an error status, like from the previous cluster validation stage. If
		// error status exists, we skip updating that role assignment status.
		var existingStatus *mrav1beta1.RoleAssignmentStatus
		for i, status := range mra.Status.RoleAssignments {
			if status.Name == roleAssignment.Name {
				existingStatus = &mra.Status.RoleAssignments[i]
				break
			}
		}

		if existingStatus != nil && existingStatus.Status == string(mrav1beta1.StatusTypeError) {
			continue
		}

		var failedClustersForRA []string
		var successClustersForRA []string

		for _, cluster := range clusters {
			if r.isRoleAssignmentTargetingCluster(roleAssignment, cluster, roleAssignmentClusters) {
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
				errorParts = append(errorParts, fmt.Sprintf("cluster %s: %v", cluster, err))
			}
			finalMessage := fmt.Sprintf("Failed on %d/%d cluster(s): %s", len(failedClustersForRA),
				len(failedClustersForRA)+len(successClustersForRA), strings.Join(errorParts, "; "))

			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypeError,
				mrav1beta1.ReasonApplicationFailed, finalMessage)
		} else if len(successClustersForRA) > 0 {
			r.setRoleAssignmentStatus(mra, roleAssignment.Name, mrav1beta1.StatusTypeActive,
				mrav1beta1.ReasonSuccessfullyApplied,
				fmt.Sprintf("Applied to %d cluster(s)", len(successClustersForRA)))
		}
	}
}

// analyzeBindingCondition inspects a condition and returns whether it is a failure or unknown/pending state.
func (r *MulticlusterRoleAssignmentReconciler) analyzeBindingCondition(
	cond *metav1.Condition, bindingName, namespace, cluster string) (isError bool, isUnknown bool, msg string) {

	if cond.Status == metav1.ConditionFalse {
		msg := fmt.Sprintf("ClusterRoleBinding %s failed on cluster %s: %s", bindingName, cluster, cond.Message)
		if namespace != "" {
			msg = fmt.Sprintf("RoleBinding %s/%s failed on cluster %s: %s", namespace, bindingName, cluster, cond.Message)
		}
		return true, false, msg
	}

	if cond.Status == metav1.ConditionUnknown {
		msg := fmt.Sprintf("ClusterRoleBinding %s pending on cluster %s: %s", bindingName, cluster, cond.Message)
		if namespace != "" {
			msg = fmt.Sprintf("RoleBinding %s/%s pending on cluster %s: %s", namespace, bindingName, cluster, cond.Message)
		}
		return false, true, msg
	}

	return false, false, ""
}

// updateRoleAssignmentStatusesFromClusterPermission checks the ClusterPermission status
// for each specific binding owned by this RoleAssignment and updates the status if there are failures.
// Returns an error if fetching ClusterPermission resources fails.
func (r *MulticlusterRoleAssignmentReconciler) updateRoleAssignmentStatusesFromClusterPermission(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment,
	roleAssignmentClusters map[string][]string, allClusters []string) error {

	clusterBindingsStatus, err := r.buildClusterBindingsStatusMap(ctx, mra, allClusters)

	if err != nil {
		return err
	}
	for _, raStatus := range mra.Status.RoleAssignments {
		r.processRoleAssignmentStatus(mra, raStatus, roleAssignmentClusters, clusterBindingsStatus)
	}

	return nil
}

// buildClusterBindingsStatusMap returns a nested map: cluster name → (binding key → Applied condition).
// This allows callers to look up the status of any binding on any cluster, for example:
//
//	condition := clusterBindingsStatus["cluster1"]["CRB:my-binding"]
//
// Binding keys use the format "CRB:<name>" for ClusterRoleBindings or "RB:<namespace>:<name>" for RoleBindings.
func (r *MulticlusterRoleAssignmentReconciler) buildClusterBindingsStatusMap(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment, allClusters []string,
) (map[string]map[string]*metav1.Condition, error) {

	clusterBindingsStatus := make(map[string]map[string]*metav1.Condition)

	for _, cluster := range allClusters {
		cp, err := r.getClusterPermission(ctx, mra, cluster)
		if err != nil {
			return nil, fmt.Errorf("failed to get ClusterPermission for cluster %s: %w", cluster, err)
		}
		// cp == nil means not found, which is expected for new clusters
		if cp == nil {
			continue
		}

		bindingMap := make(map[string]*metav1.Condition)

		// ClusterPermission-level validation conditions live on status.conditions, independent of
		// per-binding ResourceStatus. Copy each condition so later loop iterations cannot alias.
		for i := range cp.Status.Conditions {
			cond := cp.Status.Conditions[i]
			if cond.Type == cpv1alpha1.ConditionTypeValidateRolesExist ||
				cond.Type == cpv1alpha1.ConditionTypeValidateClusterRolesExist {
				bindingMap["VALIDATE:"+cond.Type] = &cond
			}
		}

		// Case caused by no available managed cluster that clusterpermission is trying to apply manifest work for
		if cp.Status.ResourceStatus == nil {
			clusterBindingsStatus[cluster] = bindingMap
			continue
		}

		if cp.Status.ResourceStatus.ClusterRoleBindings != nil {
			for _, crb := range cp.Status.ResourceStatus.ClusterRoleBindings {
				if cond := meta.FindStatusCondition(crb.Conditions, string(mrav1beta1.ConditionTypeApplied)); cond != nil {
					bindingMap["CRB:"+crb.Name] = cond
				}
			}
		}

		if cp.Status.ResourceStatus.RoleBindings != nil {
			for _, rb := range cp.Status.ResourceStatus.RoleBindings {
				if cond := meta.FindStatusCondition(rb.Conditions, string(mrav1beta1.ConditionTypeApplied)); cond != nil {
					bindingMap[fmt.Sprintf("RB:%s:%s", rb.Namespace, rb.Name)] = cond
				}
			}
		}

		clusterBindingsStatus[cluster] = bindingMap
	}
	return clusterBindingsStatus, nil
}

// processRoleAssignmentStatus updates the status for a single RoleAssignment.
// If the RoleAssignment already has an error status, any new CP binding errors are appended to the existing message.
func (r *MulticlusterRoleAssignmentReconciler) processRoleAssignmentStatus(
	mra *mrav1beta1.MulticlusterRoleAssignment,
	raStatus mrav1beta1.RoleAssignmentStatus,
	roleAssignmentClusters map[string][]string,
	clusterBindingsStatus map[string]map[string]*metav1.Condition) {

	var raSpec *mrav1beta1.RoleAssignment
	for i, ra := range mra.Spec.RoleAssignments {
		if ra.Name == raStatus.Name {
			raSpec = &mra.Spec.RoleAssignments[i]
			break
		}
	}
	if raSpec == nil {
		return
	}

	targetClusters := roleAssignmentClusters[raStatus.Name]
	if len(targetClusters) == 0 {
		return
	}

	var allErrorMessages []string
	var allUnknownMessages []string
	failedClusters := make(map[string]bool)
	pendingClusters := make(map[string]bool)
	successClusters := make(map[string]bool)

	// Loop all clusters in targetClusters and gather all Error and Unknown messages
	for _, cluster := range targetClusters {
		bindingsMap, ok := clusterBindingsStatus[cluster]
		if !ok {
			continue
		}

		if len(bindingsMap) == 0 {
			pendingClusters[cluster] = true
			allUnknownMessages = append(allUnknownMessages, fmt.Sprintf("%s is unavailable", cluster))
			continue
		}

		clusterErrors, clusterUnknowns := r.checkBindingStatusForCluster(mra, raSpec, cluster, bindingsMap)
		if len(clusterErrors) > 0 {
			failedClusters[cluster] = true
			allErrorMessages = append(allErrorMessages, clusterErrors...)
		} else if len(clusterUnknowns) > 0 {
			pendingClusters[cluster] = true
			allUnknownMessages = append(allUnknownMessages, clusterUnknowns...)
		} else {
			// No errors and no unknowns means bindings are successfully applied
			successClusters[cluster] = true
		}
	}

	// If the status is already in error state, append new CP binding errors/unknowns to the existing message
	if raStatus.Status == string(mrav1beta1.StatusTypeError) {
		if len(allErrorMessages) > 0 || len(allUnknownMessages) > 0 {
			// Combine all new issues and append to existing error message
			allIssues := append(allErrorMessages, allUnknownMessages...)
			additionalMessage := fmt.Sprintf("Additional binding issues: %s",
				strings.Join(allIssues, "; "))
			r.setRoleAssignmentStatus(mra, raStatus.Name, mrav1beta1.StatusTypeError,
				mrav1beta1.ReasonApplicationFailed, raStatus.Message+". "+additionalMessage)
		}
		// Don't overwrite existing error with pending/success - keep the error state
		return
	}

	// Build combined status message based on collected issues
	if len(allErrorMessages) > 0 {
		var finalMessage string
		allMessages := append(allErrorMessages, allUnknownMessages...)
		if len(successClusters) > 0 {
			finalMessage = fmt.Sprintf("Applied to %d cluster(s), failed on %d cluster(s), pending on %d cluster(s): %s",
				len(successClusters), len(failedClusters), len(pendingClusters), strings.Join(allMessages, "; "))
		} else if len(allUnknownMessages) > 0 {
			finalMessage = fmt.Sprintf("Failed on %d cluster(s), pending on %d cluster(s): %s",
				len(failedClusters), len(pendingClusters), strings.Join(allMessages, "; "))
		} else {
			finalMessage = fmt.Sprintf("Failed on %d cluster(s): %s",
				len(failedClusters), strings.Join(allErrorMessages, "; "))
		}
		r.setRoleAssignmentStatus(mra, raStatus.Name, mrav1beta1.StatusTypeError,
			mrav1beta1.ReasonApplicationFailed, finalMessage)
		return
	}

	if len(allUnknownMessages) > 0 {
		var finalMessage string
		if len(successClusters) > 0 {
			finalMessage = fmt.Sprintf("Applied to %d cluster(s), pending on %d cluster(s): %s",
				len(successClusters), len(pendingClusters), strings.Join(allUnknownMessages, "; "))
		} else {
			finalMessage = fmt.Sprintf("Pending on %d cluster(s): %s",
				len(pendingClusters), strings.Join(allUnknownMessages, "; "))
		}
		r.setRoleAssignmentStatus(mra, raStatus.Name, mrav1beta1.StatusTypePending,
			mrav1beta1.ReasonProcessing, finalMessage)
	}
}

// checkBindingStatusForCluster checks if any bindings for the RoleAssignment on a specific cluster are in Error or
// Unknown state.
func (r *MulticlusterRoleAssignmentReconciler) checkBindingStatusForCluster(
	mra *mrav1beta1.MulticlusterRoleAssignment,
	raSpec *mrav1beta1.RoleAssignment,
	cluster string,
	bindingsMap map[string]*metav1.Condition,
) ([]string, []string) {
	if len(raSpec.TargetNamespaces) == 0 {
		return r.checkClusterRoleBindingStatus(mra, raSpec, cluster, bindingsMap)
	}
	return r.checkRoleBindingStatus(mra, raSpec, cluster, bindingsMap)
}

// checkClusterRoleBindingStatus checks the status of a ClusterRoleBinding and returns
// slices of error messages and unknown/pending messages.
func (r *MulticlusterRoleAssignmentReconciler) checkClusterRoleBindingStatus(
	mra *mrav1beta1.MulticlusterRoleAssignment,
	raSpec *mrav1beta1.RoleAssignment,
	cluster string,
	bindingsMap map[string]*metav1.Condition,
) ([]string, []string) {
	var allErrorMsg []string
	var allUnknownMsg []string

	bindingName := r.generateBindingName(mra, raSpec.Name, raSpec.ClusterRole)
	key := "CRB:" + bindingName

	if cond := bindingsMap[key]; cond != nil {
		isError, isUnknown, msg := r.analyzeBindingCondition(cond, bindingName, "", cluster)
		if isError {
			allErrorMsg = append(allErrorMsg, msg)
		} else if isUnknown {
			allUnknownMsg = append(allUnknownMsg, msg)
		}
	}

	valErrs, valUnknowns := checkClusterRoleValidation(raSpec, cluster, bindingsMap)
	allErrorMsg = append(allErrorMsg, valErrs...)
	allUnknownMsg = append(allUnknownMsg, valUnknowns...)

	return allErrorMsg, allUnknownMsg
}

// checkRoleBindingStatus checks the status of RoleBindings for all target namespaces.
func (r *MulticlusterRoleAssignmentReconciler) checkRoleBindingStatus(
	mra *mrav1beta1.MulticlusterRoleAssignment,
	raSpec *mrav1beta1.RoleAssignment,
	cluster string,
	bindingsMap map[string]*metav1.Condition,
) ([]string, []string) {
	var allErrorMsg []string
	var allUnknownMsg []string

	for _, namespace := range raSpec.TargetNamespaces {
		bindingName := r.generateBindingName(mra, raSpec.Name, raSpec.ClusterRole, namespace)
		key := fmt.Sprintf("RB:%s:%s", namespace, bindingName)

		if cond := bindingsMap[key]; cond != nil {
			isError, isUnknown, msg := r.analyzeBindingCondition(cond, bindingName, namespace, cluster)
			if isError {
				allErrorMsg = append(allErrorMsg, msg)
			} else if isUnknown {
				allUnknownMsg = append(allUnknownMsg, msg)
			}
		}
	}

	// Namespaced RoleBindings still reference a ClusterRole, so check ClusterRole existence.
	valErrs, valUnknowns := checkClusterRoleValidation(raSpec, cluster, bindingsMap)
	allErrorMsg = append(allErrorMsg, valErrs...)
	allUnknownMsg = append(allUnknownMsg, valUnknowns...)

	return allErrorMsg, allUnknownMsg
}

// checkClusterRoleValidation reports errors or pending messages from ClusterPermission
// ValidateClusterRolesExist. Failures are attributed only when this assignment's
// ClusterRole is listed in the condition message, because multiple MRAs share one
// ClusterPermission.
func checkClusterRoleValidation(
	raSpec *mrav1beta1.RoleAssignment,
	cluster string,
	bindingsMap map[string]*metav1.Condition,
) ([]string, []string) {
	cond := bindingsMap["VALIDATE:"+cpv1alpha1.ConditionTypeValidateClusterRolesExist]
	if cond == nil || cond.Status == metav1.ConditionUnknown {
		msg := fmt.Sprintf("ClusterRole validation pending on %s", cluster)
		if cond != nil && cond.Message != "" {
			msg = fmt.Sprintf("ClusterRole validation pending on %s: %s", cluster, cond.Message)
		}
		return nil, []string{msg}
	}

	if cond.Status == metav1.ConditionFalse && roleNameInValidationMessage(cond.Message, raSpec.ClusterRole) {
		return []string{
			fmt.Sprintf("ClusterRole %q was not found on cluster %s", raSpec.ClusterRole, cluster),
		}, nil
	}

	return nil, nil
}

// roleNameInValidationMessage reports whether roleName is listed in a ClusterPermission
// validation failure message of the form:
// "The following cluster roles were not found: role-a, role-b"
func roleNameInValidationMessage(message, roleName string) bool {
	const marker = "not found: "
	idx := strings.Index(message, marker)
	if idx < 0 || roleName == "" {
		return false
	}

	for _, name := range strings.Split(message[idx+len(marker):], ", ") {
		if strings.TrimSpace(name) == roleName {
			return true
		}
	}
	return false
}

// applyClusterPermissionValidate sets ClusterPermission.spec.validate to true so
// ClusterPermission checks via ManifestWork that referenced ClusterRoles exist on spokes.
func applyClusterPermissionValidate(newSpec *cpv1alpha1.ClusterPermissionSpec) {
	enabled := true
	newSpec.Validate = &enabled
}

// ensureClusterPermission creates or updates the ClusterPermission for a specific cluster.
func (r *MulticlusterRoleAssignmentReconciler) ensureClusterPermission(ctx context.Context,
	mra *mrav1beta1.MulticlusterRoleAssignment, cluster string, roleAssignmentClusters map[string][]string) error {

	log := logf.FromContext(ctx)

	backoffConfig := wait.Backoff{
		Steps:    3,
		Duration: 10 * time.Millisecond,
		Factor:   2.0,
		Jitter:   0.1,
	}

	attemptCount := 0
	err := retry.RetryOnConflict(backoffConfig, func() error {
		attemptCount++
		if attemptCount > 1 {
			log.Info("Retrying ClusterPermission operation", "cluster", cluster, "attempt", attemptCount)
		}

		err := r.ensureClusterPermissionAttempt(ctx, mra, cluster, roleAssignmentClusters)

		if err != nil && apierrors.IsConflict(err) && attemptCount < backoffConfig.Steps {
			log.Info("ClusterPermission conflict detected, will retry", "cluster", cluster)
		}

		return err
	})

	if err != nil {
		if apierrors.IsConflict(err) {
			log.Error(err, "ClusterPermission update failed after all retry attempts due to conflicts", "cluster",
				cluster, "attempts", attemptCount)
		} else {
			log.Error(err, "ClusterPermission operation failed", "cluster", cluster, "attempt", attemptCount)
		}
		return err
	}

	return nil
}

// ensureClusterPermissionAttempt performs a single attempt to create or update a dedicated ClusterPermission for this MRA.
// It also handles migration from the legacy shared ClusterPermission model.
func (r *MulticlusterRoleAssignmentReconciler) ensureClusterPermissionAttempt(ctx context.Context,
	mra *mrav1beta1.MulticlusterRoleAssignment, cluster string, roleAssignmentClusters map[string][]string) error {

	log := logf.FromContext(ctx)
	cpName := r.generateClusterPermissionName(mra)
	mraIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)

	// Calculate desired spec for the dedicated ClusterPermission
	desiredSpec := r.calculateDesiredClusterPermissionSpec(mra, cluster, roleAssignmentClusters)

	// Get the existing dedicated ClusterPermission (if any)
	existingCP, err := r.getClusterPermission(ctx, mra, cluster)
	if err != nil {
		return err
	}

	// Handle the case where this MRA has no bindings for this cluster (cluster removed from placement)
	if r.isClusterPermissionSpecEmpty(desiredSpec) {
		// Delete the dedicated ClusterPermission if it exists
		if existingCP != nil {
			log.Info("Deleting ClusterPermission (no bindings for this cluster)", "name", cpName, "namespace", cluster)
			if err := r.Delete(ctx, existingCP); err != nil && !apierrors.IsNotFound(err) {
				return err
			}
		}
		// Also clean up any legacy bindings
		if err := r.cleanupLegacyBindings(ctx, mra, cluster); err != nil {
			return err
		}
		return nil
	}

	// Create or update the dedicated ClusterPermission
	if existingCP == nil {
		log.Info("Creating dedicated ClusterPermission", "name", cpName, "namespace", cluster)

		applyClusterPermissionValidate(&desiredSpec)
		cp := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cpName,
				Namespace: cluster,
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
				Annotations: map[string]string{
					clusterPermissionMRAOwnerAnn: mraIdentifier,
				},
			},
			Spec: desiredSpec,
		}

		if err := r.Create(ctx, cp); err != nil {
			if apierrors.IsAlreadyExists(err) {
				// Race condition - another reconcile created it. Refetch and update.
				log.Info("ClusterPermission already exists, will update instead", "name", cpName, "namespace", cluster)
				var existing cpv1alpha1.ClusterPermission
				if getErr := r.Get(ctx, client.ObjectKey{Name: cpName, Namespace: cluster}, &existing); getErr != nil {
					return getErr
				}
				// Verify this CP is managed by us and owned by this MRA
				if !r.isClusterPermissionManaged(&existing) {
					return fmt.Errorf("ClusterPermission %s/%s exists but is not managed by this controller",
						cluster, cpName)
				}
				if existing.Annotations != nil && existing.Annotations[clusterPermissionMRAOwnerAnn] != "" &&
					existing.Annotations[clusterPermissionMRAOwnerAnn] != mraIdentifier {
					return fmt.Errorf("ClusterPermission %s/%s exists but is owned by different MRA: %s",
						cluster, cpName, existing.Annotations[clusterPermissionMRAOwnerAnn])
				}
				existingCP = &existing
			} else {
				return err
			}
		} else {
			// Successfully created - DO NOT cleanup legacy bindings yet.
			// Wait until dedicated CP bindings are confirmed applied on the managed cluster.
			// Legacy cleanup happens in cleanupLegacyBindingsIfDedicatedApplied() called later.
			return nil
		}
	}

	// Update existing dedicated ClusterPermission
	applyClusterPermissionValidate(&desiredSpec)

	specChanged := !equality.Semantic.DeepEqual(existingCP.Spec, desiredSpec)
	// Ensure the owner annotation is present
	if existingCP.Annotations == nil {
		existingCP.Annotations = make(map[string]string)
	}
	annotationsChanged := existingCP.Annotations[clusterPermissionMRAOwnerAnn] != mraIdentifier

	if specChanged || annotationsChanged {
		existingCP.Spec = desiredSpec
		existingCP.Annotations[clusterPermissionMRAOwnerAnn] = mraIdentifier

		log.Info("Updating dedicated ClusterPermission", "name", cpName, "namespace", cluster)
		if err := r.Update(ctx, existingCP); err != nil {
			if apierrors.IsNotFound(err) {
				log.Info("ClusterPermission was deleted, will recreate on next reconcile")
				return nil
			}
			return err
		}
	}

	// Only clean up legacy bindings if the dedicated CP's bindings are confirmed applied.
	// This ensures we don't remove working grants before the replacement is ready.
	if r.areDedicatedCPBindingsApplied(existingCP, mra, cluster, roleAssignmentClusters) {
		if err := r.cleanupLegacyBindings(ctx, mra, cluster); err != nil {
			return err
		}
	} else {
		log.V(1).Info("Deferring legacy cleanup until dedicated CP bindings are applied",
			"name", cpName, "namespace", cluster)
	}

	return nil
}

// calculateDesiredClusterPermissionSpec computes the complete ClusterPermission spec for this MRA on this cluster.
// Unlike the old model, this is the entire spec (not a slice to merge with others).
func (r *MulticlusterRoleAssignmentReconciler) calculateDesiredClusterPermissionSpec(
	mra *mrav1beta1.MulticlusterRoleAssignment, cluster string,
	roleAssignmentClusters map[string][]string) cpv1alpha1.ClusterPermissionSpec {

	var clusterRoleBindings []cpv1alpha1.ClusterRoleBinding
	var roleBindings []cpv1alpha1.RoleBinding

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if !r.isRoleAssignmentTargetingCluster(roleAssignment, cluster, roleAssignmentClusters) {
			continue
		}

		if len(roleAssignment.TargetNamespaces) == 0 {
			bindingName := r.generateBindingName(mra, roleAssignment.Name, roleAssignment.ClusterRole)
			clusterRoleBindings = append(clusterRoleBindings, cpv1alpha1.ClusterRoleBinding{
				Name: bindingName,
				RoleRef: &rbacv1.RoleRef{
					Kind:     clusterRoleKind,
					Name:     roleAssignment.ClusterRole,
					APIGroup: rbacv1.GroupName,
				},
				Subjects: []rbacv1.Subject{convertSubject(mra.Spec.Subject)},
			})
		} else {
			for _, namespace := range roleAssignment.TargetNamespaces {
				bindingName := r.generateBindingName(mra, roleAssignment.Name, roleAssignment.ClusterRole, namespace)
				roleBindings = append(roleBindings, cpv1alpha1.RoleBinding{
					Name:      bindingName,
					Namespace: namespace,
					RoleRef: cpv1alpha1.RoleRef{
						Kind:     clusterRoleKind,
						Name:     roleAssignment.ClusterRole,
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{convertSubject(mra.Spec.Subject)},
				})
			}
		}
	}

	spec := cpv1alpha1.ClusterPermissionSpec{}

	if len(clusterRoleBindings) > 0 {
		sort.Slice(clusterRoleBindings, func(i, j int) bool {
			return clusterRoleBindings[i].Name < clusterRoleBindings[j].Name
		})
		spec.ClusterRoleBindings = &clusterRoleBindings
	}

	if len(roleBindings) > 0 {
		sort.Slice(roleBindings, func(i, j int) bool {
			return roleBindings[i].Name < roleBindings[j].Name
		})
		spec.RoleBindings = &roleBindings
	}

	// Enable ClusterRole validation on the managed cluster
	validate := true
	spec.Validate = &validate

	return spec
}

// cleanupLegacyBindings removes this MRA's bindings from the legacy shared ClusterPermission (mra-managed-permissions).
// This is the migration path from the old shared model to the new dedicated model.
func (r *MulticlusterRoleAssignmentReconciler) cleanupLegacyBindings(ctx context.Context,
	mra *mrav1beta1.MulticlusterRoleAssignment, cluster string) error {

	log := logf.FromContext(ctx)

	legacyCP, err := r.getLegacyClusterPermission(ctx, cluster)
	if err != nil {
		return fmt.Errorf("failed to get legacy ClusterPermission for migration: %w", err)
	}

	if legacyCP == nil {
		// No legacy ClusterPermission exists, nothing to migrate
		return nil
	}

	// Extract binding names owned by this MRA from the legacy ClusterPermission
	ownedBindingNames := r.extractLegacyOwnedBindingNames(legacyCP, mra)
	if len(ownedBindingNames) == 0 {
		// This MRA has no bindings in the legacy ClusterPermission
		return nil
	}

	log.Info("Migrating bindings from legacy ClusterPermission",
		"legacyCP", legacyClusterPermissionName, "namespace", cluster, "bindingsToRemove", len(ownedBindingNames))

	// Build a set of binding names to remove
	ownedBindingNamesMap := make(map[string]bool)
	for _, name := range ownedBindingNames {
		ownedBindingNamesMap[name] = true
	}

	// Remove this MRA's bindings from the legacy ClusterPermission
	var remainingCRBs []cpv1alpha1.ClusterRoleBinding
	if legacyCP.Spec.ClusterRoleBindings != nil {
		for _, crb := range *legacyCP.Spec.ClusterRoleBindings {
			if !ownedBindingNamesMap[crb.Name] {
				remainingCRBs = append(remainingCRBs, crb)
			}
		}
	}

	var remainingRBs []cpv1alpha1.RoleBinding
	if legacyCP.Spec.RoleBindings != nil {
		for _, rb := range *legacyCP.Spec.RoleBindings {
			if !ownedBindingNamesMap[rb.Name] {
				remainingRBs = append(remainingRBs, rb)
			}
		}
	}

	// Remove this MRA's owner annotations
	mraIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)
	newAnnotations := make(map[string]string)
	for key, value := range legacyCP.Annotations {
		// Keep annotations that are not owner annotations for this MRA
		if strings.HasPrefix(key, legacyOwnerAnnotationPrefix) && value == mraIdentifier {
			continue
		}
		newAnnotations[key] = value
	}

	// Check if the legacy ClusterPermission is now empty (no more MRA-managed bindings)
	hasRemainingBindings := len(remainingCRBs) > 0 || len(remainingRBs) > 0

	if !hasRemainingBindings {
		// Delete the legacy ClusterPermission
		log.Info("Deleting empty legacy ClusterPermission", "name", legacyClusterPermissionName, "namespace", cluster)
		if err := r.Delete(ctx, legacyCP); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete empty legacy ClusterPermission: %w", err)
		}
		return nil
	}

	// Update the legacy ClusterPermission with remaining bindings
	if len(remainingCRBs) > 0 {
		legacyCP.Spec.ClusterRoleBindings = &remainingCRBs
	} else {
		legacyCP.Spec.ClusterRoleBindings = nil
	}

	if len(remainingRBs) > 0 {
		legacyCP.Spec.RoleBindings = &remainingRBs
	} else {
		legacyCP.Spec.RoleBindings = nil
	}

	legacyCP.Annotations = newAnnotations

	log.Info("Updating legacy ClusterPermission to remove migrated bindings",
		"name", legacyClusterPermissionName, "namespace", cluster,
		"remainingBindings", len(remainingCRBs)+len(remainingRBs))

	if err := r.Update(ctx, legacyCP); err != nil {
		if apierrors.IsNotFound(err) {
			// Already deleted, that's fine
			return nil
		}
		return fmt.Errorf("failed to update legacy ClusterPermission: %w", err)
	}

	return nil
}

// extractLegacyOwnedBindingNames returns the list of binding names owned by this MRA
// in the legacy shared ClusterPermission, based on the old owner/* annotations.
func (r *MulticlusterRoleAssignmentReconciler) extractLegacyOwnedBindingNames(
	cp *cpv1alpha1.ClusterPermission, mra *mrav1beta1.MulticlusterRoleAssignment) []string {

	if cp == nil || cp.Annotations == nil {
		return nil
	}

	targetMRAIdentifier := r.generateMulticlusterRoleAssignmentIdentifier(mra)
	var ownedBindings []string

	for key, value := range cp.Annotations {
		if bindingName, found := strings.CutPrefix(key, legacyOwnerAnnotationPrefix); found && value == targetMRAIdentifier {
			ownedBindings = append(ownedBindings, bindingName)
		}
	}

	return ownedBindings
}

// isRoleAssignmentTargetingCluster checks if a role assignment targets a specific cluster using the pre-computed role
// assignment clusters map.
func (r *MulticlusterRoleAssignmentReconciler) isRoleAssignmentTargetingCluster(
	roleAssignment mrav1beta1.RoleAssignment, cluster string, roleAssignmentClusters map[string][]string) bool {

	clusters, exists := roleAssignmentClusters[roleAssignment.Name]
	if !exists {
		// RoleAssignment not existing means it had errors during resolution or no clusters
		return false
	}

	return slices.Contains(clusters, cluster)
}

// areDedicatedCPBindingsApplied checks if all bindings in the dedicated ClusterPermission have been
// successfully applied on the managed cluster. This is used to determine when it's safe to remove
// legacy bindings - we don't want to remove working grants before the replacement is confirmed.
func (r *MulticlusterRoleAssignmentReconciler) areDedicatedCPBindingsApplied(
	cp *cpv1alpha1.ClusterPermission, mra *mrav1beta1.MulticlusterRoleAssignment,
	cluster string, roleAssignmentClusters map[string][]string) bool {

	if cp == nil || cp.Status.ResourceStatus == nil {
		return false
	}

	// Get the expected binding names from the MRA spec
	expectedBindings := make(map[string]bool)
	for _, ra := range mra.Spec.RoleAssignments {
		if !r.isRoleAssignmentTargetingCluster(ra, cluster, roleAssignmentClusters) {
			continue
		}
		if len(ra.TargetNamespaces) == 0 {
			bindingName := r.generateBindingName(mra, ra.Name, ra.ClusterRole)
			expectedBindings[bindingName] = false
		} else {
			for _, ns := range ra.TargetNamespaces {
				bindingName := r.generateBindingName(mra, ra.Name, ra.ClusterRole, ns)
				expectedBindings[bindingName] = false
			}
		}
	}

	if len(expectedBindings) == 0 {
		// No bindings expected, nothing to verify
		return true
	}

	// Check ClusterRoleBindings
	if cp.Status.ResourceStatus.ClusterRoleBindings != nil {
		for _, crbStatus := range cp.Status.ResourceStatus.ClusterRoleBindings {
			if _, expected := expectedBindings[crbStatus.Name]; expected {
				for _, cond := range crbStatus.Conditions {
					if cond.Type == conditionTypeApplied && cond.Status == metav1.ConditionTrue {
						expectedBindings[crbStatus.Name] = true
						break
					}
				}
			}
		}
	}

	// Check RoleBindings
	if cp.Status.ResourceStatus.RoleBindings != nil {
		for _, rbStatus := range cp.Status.ResourceStatus.RoleBindings {
			if _, expected := expectedBindings[rbStatus.Name]; expected {
				for _, cond := range rbStatus.Conditions {
					if cond.Type == conditionTypeApplied && cond.Status == metav1.ConditionTrue {
						expectedBindings[rbStatus.Name] = true
						break
					}
				}
			}
		}
	}

	// All expected bindings must be applied
	for _, applied := range expectedBindings {
		if !applied {
			return false
		}
	}
	return true
}

// clearStaleStatus clears status information that may be stale due to spec changes.
func (r *MulticlusterRoleAssignmentReconciler) clearStaleStatus(mra *mrav1beta1.MulticlusterRoleAssignment) {
	for i, condition := range mra.Status.Conditions {
		if condition.Type == string(mrav1beta1.ConditionTypeApplied) {
			mra.Status.Conditions[i].Status = metav1.ConditionFalse
			mra.Status.Conditions[i].Reason = string(mrav1beta1.ReasonApplyInProgress)
			mra.Status.Conditions[i].Message = "Re-evaluating ClusterPermissions"
			mra.Status.Conditions[i].LastTransitionTime = metav1.Now()
			mra.Status.Conditions[i].ObservedGeneration = mra.Generation
			break
		}
	}

	currentRoleAssignmentNames := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		currentRoleAssignmentNames[roleAssignment.Name] = true
	}

	var currentRoleAssignmentStatuses []mrav1beta1.RoleAssignmentStatus
	for _, status := range mra.Status.RoleAssignments {
		if currentRoleAssignmentNames[status.Name] {
			status.Status = string(mrav1beta1.StatusTypePending)
			status.Reason = string(mrav1beta1.ReasonProcessing)
			status.Message = "Re-evaluating"
			currentRoleAssignmentStatuses = append(currentRoleAssignmentStatuses, status)
		}
	}
	mra.Status.RoleAssignments = currentRoleAssignmentStatuses
}

// generateBindingName creates a deterministic and unique binding name using all key binding properties. This ensures
// different bindings get different names even when they share some properties. Binding name must be unique or else
// ClusterPermission may fail to apply it.
func (r *MulticlusterRoleAssignmentReconciler) generateBindingName(mra *mrav1beta1.MulticlusterRoleAssignment,
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

// generateClusterPermissionName creates a deterministic, DNS-valid ClusterPermission name for an MRA.
// The name is stable across reconciliations, unique within a managed-cluster namespace, and ≤63 characters.
// Format: mra-<sanitized-mra-name>-<8-char-hash>
func (r *MulticlusterRoleAssignmentReconciler) generateClusterPermissionName(
	mra *mrav1beta1.MulticlusterRoleAssignment) string {

	// Hash includes both namespace and name for uniqueness across namespaces
	data := fmt.Sprintf("%s/%s", mra.Namespace, mra.Name)
	h := sha256.Sum256([]byte(data))
	hash := hex.EncodeToString(h[:])[:8]

	// Sanitize the MRA name for DNS compatibility
	invalidCharsRegex := regexp.MustCompile(`[^a-z0-9-]`)
	sanitizedName := strings.ToLower(mra.Name)
	sanitizedName = invalidCharsRegex.ReplaceAllString(sanitizedName, "-")
	sanitizedName = strings.Trim(sanitizedName, "-")

	// Collapse multiple consecutive dashes
	multiDashRegex := regexp.MustCompile(`-+`)
	sanitizedName = multiDashRegex.ReplaceAllString(sanitizedName, "-")

	// Prefix "mra-" (4 chars) + hash "-xxxxxxxx" (9 chars) = 13 chars reserved
	// Max name length is 63, so sanitized name can be at most 50 chars
	const maxSanitizedLength = 50
	if len(sanitizedName) > maxSanitizedLength {
		sanitizedName = sanitizedName[:maxSanitizedLength]
		sanitizedName = strings.TrimRight(sanitizedName, "-")
	}

	return fmt.Sprintf("mra-%s-%s", sanitizedName, hash)
}

// generateLegacyOwnerAnnotationKey creates the legacy ClusterPermission annotation key for tracking binding ownership.
// Used only for migration from the shared ClusterPermission model.
func (r *MulticlusterRoleAssignmentReconciler) generateLegacyOwnerAnnotationKey(bindingName string) string {
	return legacyOwnerAnnotationPrefix + bindingName
}

// generateMulticlusterRoleAssignmentIdentifier creates the MulticlusterRoleAssignment identifier stored as annotation
// value in the ClusterPermission owner binding annotation.
func (r *MulticlusterRoleAssignmentReconciler) generateMulticlusterRoleAssignmentIdentifier(
	mra *mrav1beta1.MulticlusterRoleAssignment) string {

	return fmt.Sprintf("%s/%s", mra.Namespace, mra.Name)
}

// convertSubject converts a v1beta1.Subject to rbacv1.Subject for use in role bindings.
func convertSubject(s mrav1beta1.Subject) rbacv1.Subject {
	return rbacv1.Subject{
		Kind:      s.Kind,
		APIGroup:  s.APIGroup,
		Name:      s.Name,
		Namespace: s.Namespace,
	}
}

// isClusterPermissionSpecEmpty returns true if the ClusterPermissionSpec has no bindings.
func (r *MulticlusterRoleAssignmentReconciler) isClusterPermissionSpecEmpty(
	spec cpv1alpha1.ClusterPermissionSpec) bool {

	return (spec.ClusterRoleBindings == nil || len(*spec.ClusterRoleBindings) == 0) &&
		(spec.RoleBindings == nil || len(*spec.RoleBindings) == 0)
}

func (r *MulticlusterRoleAssignmentReconciler) handleMulticlusterRoleAssignmentDeletion(
	ctx context.Context, mra *mrav1beta1.MulticlusterRoleAssignment) error {

	log := logf.FromContext(ctx)

	log.Info("Handling MulticlusterRoleAssignment deletion")

	currentClusters, _, err := r.aggregateClusters(ctx, mra)
	if err != nil {
		// Transient error during deletion - retry to ensure complete cleanup
		log.Error(err, "Failed to aggregate clusters during deletion, will retry")
		return err
	}

	// Include previously applied clusters to ensure complete cleanup even if role assignments were removed from spec
	// before deletion
	previousClusters := mra.Status.AppliedClusters
	if previousClusters == nil {
		previousClusters = []string{}
	}

	missingClusters := utils.FindDifference(previousClusters, currentClusters)
	clustersToCleanup := append(append([]string{}, currentClusters...), missingClusters...)

	// Create an empty MRA copy to represent the desired state (no bindings)
	emptyMRA := mra.DeepCopy()
	emptyMRA.Spec.RoleAssignments = []mrav1beta1.RoleAssignment{}

	// Create empty clusters map for deletion (emptyMRA has no RoleAssignments)
	emptyClusters := make(map[string][]string)

	var cleanupErrors []error

	for _, cluster := range clustersToCleanup {
		log.Info("Processing ClusterPermission cleanup for cluster", "cluster", cluster)

		if err := r.ensureClusterPermission(ctx, emptyMRA, cluster, emptyClusters); err != nil {
			log.Error(err, "Failed to cleanup ClusterPermission for cluster", "cluster", cluster)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("cluster %s: %w", cluster, err))
		}
	}

	if len(cleanupErrors) > 0 {
		log.Error(fmt.Errorf("cleanup failed for %d/%d clusters", len(cleanupErrors), len(clustersToCleanup)),
			"MulticlusterRoleAssignment deletion completed with errors", "failedClusters", len(cleanupErrors),
			"totalClusters", len(clustersToCleanup))
		return fmt.Errorf("failed to cleanup %d/%d clusters during deletion: %v",
			len(cleanupErrors), len(clustersToCleanup), cleanupErrors)
	}

	return nil
}

// findMRAsForPlacementDecision maps a PlacementDecision to the MRAs that reference its Placement
func (r *MulticlusterRoleAssignmentReconciler) findMRAsForPlacementDecision(
	ctx context.Context, obj client.Object) []reconcile.Request {

	log := logf.FromContext(ctx)

	pd, ok := obj.(*clusterv1beta1.PlacementDecision)
	if !ok {
		log.Error(fmt.Errorf("unexpected object type"), "Expected PlacementDecision", "got", obj)
		return nil
	}

	// Get the Placement name from the PlacementDecision label
	placementName := pd.Labels[clusterv1beta1.PlacementLabel]
	if placementName == "" {
		log.Info("PlacementDecision has no placement label, skipping", "placementDecision", pd.Name)
		return nil
	}

	placementKey := fmt.Sprintf("%s/%s", pd.Namespace, placementName)

	var mraList mrav1beta1.MulticlusterRoleAssignmentList
	if err := r.List(ctx, &mraList, client.MatchingFields{placementIndexField: placementKey}); err != nil {
		log.Error(err, "Failed to list MulticlusterRoleAssignments for PlacementDecision mapping")
		return nil
	}

	requests := make([]reconcile.Request, 0, len(mraList.Items))
	for _, mra := range mraList.Items {
		requests = append(requests, reconcile.Request{
			NamespacedName: types.NamespacedName{
				Namespace: mra.Namespace,
				Name:      mra.Name,
			},
		})
		log.Info("PlacementDecision change detected, queueing MRA for reconciliation",
			"placementDecision", pd.Name,
			"placement", placementName,
			"mra", mra.Namespace+"/"+mra.Name)
	}

	return requests
}

// SetupWithManager sets up the controller with the Manager.
func (r *MulticlusterRoleAssignmentReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&mrav1beta1.MulticlusterRoleAssignment{},
			builder.WithPredicates(predicate.Or(
				predicate.GenerationChangedPredicate{},
				deletionTimestampSetPredicate,
			))).
		Watches(
			&cpv1alpha1.ClusterPermission{},
			&clusterPermissionEventHandler{},
			builder.WithPredicates(
				predicate.And(
					predicate.NewPredicateFuncs(r.isClusterPermissionManaged),
					predicate.Funcs{
						UpdateFunc: func(e event.UpdateEvent) bool {
							oldCP := e.ObjectOld.(*cpv1alpha1.ClusterPermission)
							newCP := e.ObjectNew.(*cpv1alpha1.ClusterPermission)
							if oldCP.Generation != newCP.Generation {
								return true
							}
							if !equality.Semantic.DeepEqual(oldCP.Status.ResourceStatus, newCP.Status.ResourceStatus) {
								return true
							}
							// Trigger reconciliation when validation conditions change (e.g., role existence status)
							if validationConditionsChanged(oldCP, newCP) {
								return true
							}
							// Trigger reconciliation when ownership annotation changes.
							// This ensures the original MRA is notified if its CP's owner is removed or changed.
							oldOwner := ""
							newOwner := ""
							if oldCP.Annotations != nil {
								oldOwner = oldCP.Annotations[clusterPermissionMRAOwnerAnn]
							}
							if newCP.Annotations != nil {
								newOwner = newCP.Annotations[clusterPermissionMRAOwnerAnn]
							}
							return oldOwner != newOwner
						},
						CreateFunc: func(e event.CreateEvent) bool {
							return true
						},
						DeleteFunc: func(e event.DeleteEvent) bool {
							return true
						},
					},
				),
			),
		).
		Watches(
			&clusterv1beta1.PlacementDecision{},
			handler.EnqueueRequestsFromMapFunc(r.findMRAsForPlacementDecision),
			builder.WithPredicates(predicate.Funcs{
				CreateFunc: func(e event.CreateEvent) bool {
					return true // Handler filters via field index
				},
				UpdateFunc: func(e event.UpdateEvent) bool {
					oldPD := e.ObjectOld.(*clusterv1beta1.PlacementDecision)
					newPD := e.ObjectNew.(*clusterv1beta1.PlacementDecision)
					// Only trigger if cluster decisions actually changed
					return !equality.Semantic.DeepEqual(oldPD.Status.Decisions, newPD.Status.Decisions)
				},
				DeleteFunc: func(e event.DeleteEvent) bool {
					return true // Handler filters via field index
				},
			}),
		).
		Named("multiclusterroleassignment").
		Complete(r)
}
