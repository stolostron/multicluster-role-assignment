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

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	clusterpermissionv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

// clusterPermissionEventHandler is a custom event handler that intelligently determines which MRAs need to be
// reconciled based on which specific bindings changed in a ClusterPermission.
type clusterPermissionEventHandler struct {
	client client.Client
}

// Create handles ClusterPermission creation events
func (h *clusterPermissionEventHandler) Create(ctx context.Context, e event.TypedCreateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	log := logf.FromContext(ctx)
	cp := e.Object.(*clusterpermissionv1alpha1.ClusterPermission)

	log.Info("ClusterPermission created, reconciling all owner MulticlusterRoleAssignments",
		"clusterPermission", cp.Name, "namespace", cp.Namespace)

	h.enqueueAllOwners(ctx, cp, q)
}

// Update handles ClusterPermission update events with diffing
func (h *clusterPermissionEventHandler) Update(ctx context.Context, e event.TypedUpdateEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	log := logf.FromContext(ctx)
	oldCP := e.ObjectOld.(*clusterpermissionv1alpha1.ClusterPermission)
	newCP := e.ObjectNew.(*clusterpermissionv1alpha1.ClusterPermission)

	affectedMRAs := h.findAffectedMRAs(oldCP, newCP)

	if len(affectedMRAs) == 0 {
		return
	}

	log.Info("ClusterPermission bindings changed, reconciling affected MulticlusterRoleAssignments only",
		"clusterPermission", newCP.Name, "namespace", newCP.Namespace, "affectedMRAs", len(affectedMRAs),
		"totalOwners", len(h.extractAllOwners(newCP)))

	for mraID := range affectedMRAs {
		h.enqueueMRA(mraID, q, log)
	}
}

// Delete handles ClusterPermission deletion events
func (h *clusterPermissionEventHandler) Delete(ctx context.Context, e event.TypedDeleteEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	log := logf.FromContext(ctx)
	cp := e.Object.(*clusterpermissionv1alpha1.ClusterPermission)

	log.Info("ClusterPermission deleted, reconciling all owner MulticlusterRoleAssignment", "clusterPermission", cp.Name,
		"namespace", cp.Namespace)

	h.enqueueAllOwners(ctx, cp, q)
}

func (h *clusterPermissionEventHandler) Generic(ctx context.Context, e event.TypedGenericEvent[client.Object],
	q workqueue.TypedRateLimitingInterface[reconcile.Request]) {
	// Not used; only needed to satisfy interface
}

// findAffectedMRAs identifies which MRAs are affected by comparing old vs new bindings
func (h *clusterPermissionEventHandler) findAffectedMRAs(
	oldCP, newCP *clusterpermissionv1alpha1.ClusterPermission) map[string]bool {

	affectedMRAs := make(map[string]bool)

	oldClusterRoleBindings := h.buildClusterRoleBindingMap(oldCP)
	newClusterRoleBindings := h.buildClusterRoleBindingMap(newCP)
	oldRoleBindings := h.buildRoleBindingMap(oldCP)
	newRoleBindings := h.buildRoleBindingMap(newCP)

	h.compareClusterRoleBindings(oldClusterRoleBindings, newClusterRoleBindings, oldCP, newCP, affectedMRAs)
	h.compareRoleBindings(oldRoleBindings, newRoleBindings, oldCP, newCP, affectedMRAs)

	if h.hasOrphanedBindings(newCP, newClusterRoleBindings, newRoleBindings) {
		// Orphaned bindings detected - reconcile all owners to clean up
		return h.extractAllOwners(newCP)
	}

	return affectedMRAs
}

// buildClusterRoleBindingMap creates a map of binding name -> binding
func (h *clusterPermissionEventHandler) buildClusterRoleBindingMap(
	cp *clusterpermissionv1alpha1.ClusterPermission) map[string]clusterpermissionv1alpha1.ClusterRoleBinding {

	bindingMap := make(map[string]clusterpermissionv1alpha1.ClusterRoleBinding)
	if cp.Spec.ClusterRoleBindings != nil {
		for _, binding := range *cp.Spec.ClusterRoleBindings {
			bindingMap[binding.Name] = binding
		}
	}

	return bindingMap
}

// buildRoleBindingMap creates a map of namespace/name -> binding
func (h *clusterPermissionEventHandler) buildRoleBindingMap(
	cp *clusterpermissionv1alpha1.ClusterPermission) map[string]clusterpermissionv1alpha1.RoleBinding {

	bindingMap := make(map[string]clusterpermissionv1alpha1.RoleBinding)
	if cp.Spec.RoleBindings != nil {
		for _, binding := range *cp.Spec.RoleBindings {
			key := binding.Namespace + "/" + binding.Name
			bindingMap[key] = binding
		}
	}
	return bindingMap
}

// compareClusterRoleBindings compares old and new ClusterRoleBindings and identifies affected MRAs
func (h *clusterPermissionEventHandler) compareClusterRoleBindings(
	oldBindings, newBindings map[string]clusterpermissionv1alpha1.ClusterRoleBinding,
	oldCP, newCP *clusterpermissionv1alpha1.ClusterPermission,
	affectedMRAs map[string]bool) {

	for name, newBinding := range newBindings {
		oldBinding, exists := oldBindings[name]

		if !exists {
			// Binding added - look up owner in new CP
			if owner := h.getOwnerFromAnnotation(newCP, name); owner != "" {
				affectedMRAs[owner] = true
			}
		} else if !equality.Semantic.DeepEqual(oldBinding, newBinding) {
			// Binding modified - look up owner in new CP
			if owner := h.getOwnerFromAnnotation(newCP, name); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}

	for name := range oldBindings {
		if _, exists := newBindings[name]; !exists {
			// Binding removed - look up owner in old CP (annotation removed from new8)
			if owner := h.getOwnerFromAnnotation(oldCP, name); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}
}

// compareRoleBindings compares old and new RoleBindings and identifies affected MRAs
func (h *clusterPermissionEventHandler) compareRoleBindings(
	oldBindings, newBindings map[string]clusterpermissionv1alpha1.RoleBinding,
	oldCP, newCP *clusterpermissionv1alpha1.ClusterPermission,
	affectedMRAs map[string]bool) {

	for key, newBinding := range newBindings {
		oldBinding, exists := oldBindings[key]

		if !exists {
			// Binding added - look up owner in new CP
			if owner := h.getOwnerFromAnnotation(newCP, newBinding.Name); owner != "" {
				affectedMRAs[owner] = true
			}
		} else if !equality.Semantic.DeepEqual(oldBinding, newBinding) {
			// Binding modified - look up owner in new CP
			if owner := h.getOwnerFromAnnotation(newCP, newBinding.Name); owner != "" {
				affectedMRAs[owner] = true
			}
		}
	}

	for key := range oldBindings {
		if _, exists := newBindings[key]; !exists {
			parts := strings.Split(key, "/")
			if len(parts) == 2 {
				// Binding removed - look up owner in old CP (annotation removed from new)
				if owner := h.getOwnerFromAnnotation(oldCP, parts[1]); owner != "" {
					affectedMRAs[owner] = true
				}
			}
		}
	}
}

// getOwnerFromAnnotation retrieves the MRA owner identifier for a given binding name
func (h *clusterPermissionEventHandler) getOwnerFromAnnotation(
	cp *clusterpermissionv1alpha1.ClusterPermission, bindingName string) string {

	if cp.Annotations == nil {
		return ""
	}
	ownerKey := OwnerAnnotationPrefix + bindingName

	return cp.Annotations[ownerKey]
}

// hasOrphanedBindings checks if any bindings exist without owner annotations
func (h *clusterPermissionEventHandler) hasOrphanedBindings(cp *clusterpermissionv1alpha1.ClusterPermission,
	clusterRoleBindings map[string]clusterpermissionv1alpha1.ClusterRoleBinding,
	roleBindings map[string]clusterpermissionv1alpha1.RoleBinding) bool {

	for name := range clusterRoleBindings {
		if h.getOwnerFromAnnotation(cp, name) == "" {
			return true
		}
	}

	for _, binding := range roleBindings {
		if h.getOwnerFromAnnotation(cp, binding.Name) == "" {
			return true
		}
	}

	return false
}

// extractAllOwners extracts all MRA owner identifiers from ClusterPermission annotations
func (h *clusterPermissionEventHandler) extractAllOwners(
	cp *clusterpermissionv1alpha1.ClusterPermission) map[string]bool {

	owners := make(map[string]bool)
	if cp.Annotations != nil {
		for key, value := range cp.Annotations {
			if strings.HasPrefix(key, OwnerAnnotationPrefix) {
				owners[value] = true
			}
		}
	}
	return owners
}

// enqueueAllOwners enqueues reconcile requests for all MRAs that own this ClusterPermission
func (h *clusterPermissionEventHandler) enqueueAllOwners(ctx context.Context,
	cp *clusterpermissionv1alpha1.ClusterPermission, q workqueue.TypedRateLimitingInterface[reconcile.Request]) {

	log := logf.FromContext(ctx)
	owners := h.extractAllOwners(cp)

	for mraID := range owners {
		h.enqueueMRA(mraID, q, log)
	}
}

// enqueueMRA adds a reconcile request for the specified MRA to the workqueue
func (h *clusterPermissionEventHandler) enqueueMRA(
	mraID string, q workqueue.TypedRateLimitingInterface[reconcile.Request], log logr.Logger) {

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
