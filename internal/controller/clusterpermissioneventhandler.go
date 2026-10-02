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

	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// clusterPermissionEventHandler is a custom event handler that determines which MRAs need to be
// reconciled when a ClusterPermission changes.
//
// With the new dedicated ClusterPermission model, each ClusterPermission is owned by exactly one MRA
// (identified by the clusterPermissionMRAOwnerAnn annotation). Status changes in the ClusterPermission
// trigger reconciliation of the owning MRA.
//
// For legacy ClusterPermissions (mra-managed-permissions), the handler falls back to the old
// per-binding owner annotations (legacyOwnerAnnotationPrefix) for migration purposes.
type clusterPermissionEventHandler struct{}

// Create handles ClusterPermission creation events
func (h *clusterPermissionEventHandler) Create(ctx context.Context, e event.TypedCreateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	cp := e.Object.(*cpv1alpha1.ClusterPermission)
	enqueueOwner(ctx, cp, q)
}

// Update handles ClusterPermission update events
func (h *clusterPermissionEventHandler) Update(ctx context.Context, e event.TypedUpdateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	oldCP := e.ObjectOld.(*cpv1alpha1.ClusterPermission)
	newCP := e.ObjectNew.(*cpv1alpha1.ClusterPermission)

	// Get old and new owner annotations
	oldOwner := ""
	newOwner := ""
	if oldCP.Annotations != nil {
		oldOwner = oldCP.Annotations[clusterPermissionMRAOwnerAnn]
	}
	if newCP.Annotations != nil {
		newOwner = newCP.Annotations[clusterPermissionMRAOwnerAnn]
	}

	// If ownership changed, enqueue BOTH the old and new owner MRAs.
	// This ensures the original owner is notified when its CP is stolen or its owner annotation removed.
	if oldOwner != newOwner {
		if oldOwner != "" {
			enqueueMRA(ctx, oldOwner, q)
		}
		if newOwner != "" {
			enqueueMRA(ctx, newOwner, q)
		}
		return
	}

	// For normal updates (no ownership change), just enqueue the current owner
	enqueueOwner(ctx, newCP, q)
}

// Delete handles ClusterPermission deletion events
func (h *clusterPermissionEventHandler) Delete(ctx context.Context, e event.TypedDeleteEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	cp := e.Object.(*cpv1alpha1.ClusterPermission)
	enqueueOwner(ctx, cp, q)
}

func (h *clusterPermissionEventHandler) Generic(ctx context.Context, e event.TypedGenericEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	// Not used; only needed to satisfy interface
}

// enqueueOwner enqueues the owning MRA for reconciliation.
// For new dedicated ClusterPermissions, the owner is identified by clusterPermissionMRAOwnerAnn.
// For legacy shared ClusterPermissions, all owners are enqueued based on legacyOwnerAnnotationPrefix.
func enqueueOwner(ctx context.Context, cp *cpv1alpha1.ClusterPermission,
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	if cp.Annotations == nil {
		return
	}

	// Check for the new dedicated owner annotation first
	if mraID := cp.Annotations[clusterPermissionMRAOwnerAnn]; mraID != "" {
		enqueueMRA(ctx, mraID, q)
		return
	}

	// Fall back to legacy per-binding owner annotations for migration
	enqueueAllLegacyOwners(ctx, cp, q)
}

// enqueueAllLegacyOwners enqueues all MRAs that own bindings in a legacy shared ClusterPermission.
func enqueueAllLegacyOwners(ctx context.Context, cp *cpv1alpha1.ClusterPermission,
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	owners := extractAllLegacyOwners(cp)
	for mraID := range owners {
		enqueueMRA(ctx, mraID, q)
	}
}

// extractAllLegacyOwners extracts all MRA owner identifiers from legacy per-binding annotations.
func extractAllLegacyOwners(cp *cpv1alpha1.ClusterPermission) map[string]bool {
	owners := make(map[string]bool)
	if cp.Annotations != nil {
		for key, value := range cp.Annotations {
			if strings.HasPrefix(key, legacyOwnerAnnotationPrefix) {
				owners[value] = true
			}
		}
	}
	return owners
}

// validationConditionsChanged reports whether ClusterPermission role-existence
// validation conditions were added, removed, or updated.
func validationConditionsChanged(oldCP, newCP *cpv1alpha1.ClusterPermission) bool {
	return !equality.Semantic.DeepEqual(filterValidationConditions(oldCP), filterValidationConditions(newCP))
}

func filterValidationConditions(cp *cpv1alpha1.ClusterPermission) []metav1.Condition {
	if cp == nil {
		return nil
	}
	var conds []metav1.Condition
	for _, cond := range cp.Status.Conditions {
		if cond.Type == cpv1alpha1.ConditionTypeValidateRolesExist ||
			cond.Type == cpv1alpha1.ConditionTypeValidateClusterRolesExist {
			conds = append(conds, cond)
		}
	}
	return conds
}

// enqueueMRA adds a reconcile request for the specified MRA to the workqueue
func enqueueMRA(ctx context.Context, mraID string, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	log := logf.FromContext(ctx)
	namespaceName := strings.Split(mraID, "/")
	if len(namespaceName) != 2 || namespaceName[0] == "" || namespaceName[1] == "" {
		log.Error(fmt.Errorf("invalid MRA identifier format"), "Invalid MRA identifier in ClusterPermission annotation",
			"identifier", mraID, "expected", "namespace/name")
		return
	}

	q.Add(reconcile.Request{
		NamespacedName: types.NamespacedName{
			Namespace: namespaceName[0],
			Name:      namespaceName[1],
		},
	})
}
