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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// clusterPermissionEventHandler is a custom event handler that intelligently determines which MRAs need to be
// reconciled based on which specific bindings changed in a ClusterPermission.
type clusterPermissionEventHandler struct{}

// Create handles ClusterPermission creation events
func (h *clusterPermissionEventHandler) Create(ctx context.Context, e event.TypedCreateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	cp := e.Object.(*cpv1alpha1.ClusterPermission)
	enqueueAllOwners(ctx, cp, q)
}

// Update handles ClusterPermission update events with diffing
func (h *clusterPermissionEventHandler) Update(ctx context.Context, e event.TypedUpdateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	oldCP := e.ObjectOld.(*cpv1alpha1.ClusterPermission)
	newCP := e.ObjectNew.(*cpv1alpha1.ClusterPermission)

	affectedMRAs := findAffectedMRAs(oldCP, newCP)

	if len(affectedMRAs) == 0 {
		return
	}

	for mraID := range affectedMRAs {
		enqueueMRA(ctx, mraID, q)
	}
}

// Delete handles ClusterPermission deletion events
func (h *clusterPermissionEventHandler) Delete(ctx context.Context, e event.TypedDeleteEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	cp := e.Object.(*cpv1alpha1.ClusterPermission)
	enqueueAllOwners(ctx, cp, q)
}

func (h *clusterPermissionEventHandler) Generic(ctx context.Context, e event.TypedGenericEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	// Not used; only needed to satisfy interface
}

// findAffectedMRAs identifies which MRAs are affected by comparing old vs new bindings
func findAffectedMRAs(oldCP, newCP *cpv1alpha1.ClusterPermission) map[string]bool {
	affectedMRAs := make(map[string]bool)

	oldClusterRoleBindings := buildClusterRoleBindingMap(oldCP)
	newClusterRoleBindings := buildClusterRoleBindingMap(newCP)
	oldRoleBindings := buildRoleBindingMap(oldCP)
	newRoleBindings := buildRoleBindingMap(newCP)

	compareBindings(oldClusterRoleBindings, newClusterRoleBindings, oldCP, newCP, affectedMRAs,
		func(b cpv1alpha1.ClusterRoleBinding) string { return b.Name })
	compareBindings(oldRoleBindings, newRoleBindings, oldCP, newCP, affectedMRAs,
		func(b cpv1alpha1.RoleBinding) string { return b.Name })

	// Check for status changes
	oldClusterRoleBindingStatus := buildClusterRoleBindingStatusMap(oldCP)
	newClusterRoleBindingStatus := buildClusterRoleBindingStatusMap(newCP)
	compareStatus(oldClusterRoleBindingStatus, newClusterRoleBindingStatus, newCP, affectedMRAs,
		func(b cpv1alpha1.ClusterRoleBindingStatus) string { return b.Name })

	oldRoleBindingStatus := buildRoleBindingStatusMap(oldCP)
	newRoleBindingStatus := buildRoleBindingStatusMap(newCP)
	compareStatus(oldRoleBindingStatus, newRoleBindingStatus, newCP, affectedMRAs,
		func(b cpv1alpha1.RoleBindingStatus) string { return b.Name })

	if hasOrphanedBindings(newCP, newClusterRoleBindings, newRoleBindings) {
		// Orphaned bindings detected - reconcile all owners to clean up
		return extractAllOwners(newCP)
	}

	return affectedMRAs
}

// buildClusterRoleBindingMap creates a map of binding name -> binding
func buildClusterRoleBindingMap(
	cp *cpv1alpha1.ClusterPermission) map[string]cpv1alpha1.ClusterRoleBinding {

	bindingMap := make(map[string]cpv1alpha1.ClusterRoleBinding)
	if cp.Spec.ClusterRoleBindings != nil {
		for _, binding := range *cp.Spec.ClusterRoleBindings {
			bindingMap[binding.Name] = binding
		}
	}

	return bindingMap
}

// buildRoleBindingMap creates a map of namespace/name -> binding
func buildRoleBindingMap(
	cp *cpv1alpha1.ClusterPermission) map[string]cpv1alpha1.RoleBinding {

	bindingMap := make(map[string]cpv1alpha1.RoleBinding)
	if cp.Spec.RoleBindings != nil {
		for _, binding := range *cp.Spec.RoleBindings {
			key := binding.Namespace + "/" + binding.Name
			bindingMap[key] = binding
		}
	}
	return bindingMap
}

// compareBindings compares old and new bindings and identifies affected MRAs
func compareBindings[T any](
	oldBindings, newBindings map[string]T,
	oldCP, newCP *cpv1alpha1.ClusterPermission,
	affectedMRAs map[string]bool,
	getBindingName func(T) string) {

	for key, newBinding := range newBindings {
		oldBinding, exists := oldBindings[key]

		// Binding added or modified - look up owner in new CP
		if !exists || !equality.Semantic.DeepEqual(oldBinding, newBinding) {
			if owner := getOwnerFromAnnotation(newCP, getBindingName(newBinding)); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}

	for key, oldBinding := range oldBindings {
		if _, exists := newBindings[key]; !exists {
			// Binding removed - look up owner in old CP
			if owner := getOwnerFromAnnotation(oldCP, getBindingName(oldBinding)); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}
}

// getOwnerFromAnnotation retrieves the MRA owner identifier for a given binding name
func getOwnerFromAnnotation(cp *cpv1alpha1.ClusterPermission, bindingName string) string {
	if cp.Annotations == nil {
		return ""
	}
	ownerKey := ownerAnnotationPrefix + bindingName

	return cp.Annotations[ownerKey]
}

// hasOrphanedBindings checks if any bindings exist without owner annotations
func hasOrphanedBindings(cp *cpv1alpha1.ClusterPermission, clusterRoleBindings map[string]cpv1alpha1.ClusterRoleBinding,
	roleBindings map[string]cpv1alpha1.RoleBinding) bool {

	for name := range clusterRoleBindings {
		if getOwnerFromAnnotation(cp, name) == "" {
			return true
		}
	}

	for _, binding := range roleBindings {
		if getOwnerFromAnnotation(cp, binding.Name) == "" {
			return true
		}
	}

	return false
}

// extractAllOwners extracts all MRA owner identifiers from ClusterPermission annotations
func extractAllOwners(cp *cpv1alpha1.ClusterPermission) map[string]bool {
	owners := make(map[string]bool)
	if cp.Annotations != nil {
		for key, value := range cp.Annotations {
			if strings.HasPrefix(key, ownerAnnotationPrefix) {
				owners[value] = true
			}
		}
	}
	return owners
}

// enqueueAllOwners enqueues reconcile requests for all MRAs that own this ClusterPermission
func enqueueAllOwners(ctx context.Context, cp *cpv1alpha1.ClusterPermission,
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	owners := extractAllOwners(cp)

	for mraID := range owners {
		enqueueMRA(ctx, mraID, q)
	}
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

// buildClusterRoleBindingStatusMap creates a map of binding name -> binding status
func buildClusterRoleBindingStatusMap(
	cp *cpv1alpha1.ClusterPermission) map[string]cpv1alpha1.ClusterRoleBindingStatus {

	statusMap := make(map[string]cpv1alpha1.ClusterRoleBindingStatus)
	if cp.Status.ResourceStatus != nil && cp.Status.ResourceStatus.ClusterRoleBindings != nil {
		for _, status := range cp.Status.ResourceStatus.ClusterRoleBindings {
			statusMap[status.Name] = status
		}
	}
	return statusMap
}

// buildRoleBindingStatusMap creates a map of namespace/name -> binding status
func buildRoleBindingStatusMap(
	cp *cpv1alpha1.ClusterPermission) map[string]cpv1alpha1.RoleBindingStatus {

	statusMap := make(map[string]cpv1alpha1.RoleBindingStatus)
	if cp.Status.ResourceStatus != nil && cp.Status.ResourceStatus.RoleBindings != nil {
		for _, status := range cp.Status.ResourceStatus.RoleBindings {
			// Use namespace/name as key to match how buildRoleBindingMap works
			key := status.Namespace + "/" + status.Name
			statusMap[key] = status
		}
	}
	return statusMap
}

// compareStatus compares old and new status and identifies affected MRAs.
// Only status additions and modifications trigger reconciliation. Status removals are ignored
// because they indicate the binding was removed and the CP controller cleaned up the status -
// the MRA already reconciles off the spec change when a binding is removed.
func compareStatus[T any](
	oldStatus, newStatus map[string]T,
	newCP *cpv1alpha1.ClusterPermission,
	affectedMRAs map[string]bool,
	getBindingName func(T) string) {

	for key, newS := range newStatus {
		oldS, exists := oldStatus[key]

		// Status added or modified - look up owner in new CP
		if !exists || !equality.Semantic.DeepEqual(oldS, newS) {
			if owner := getOwnerFromAnnotation(newCP, getBindingName(newS)); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}
}
