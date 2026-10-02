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
	"maps"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
)

func TestEventHandlers_Create_DedicatedCP(t *testing.T) {
	tests := []struct {
		name         string
		cp           client.Object
		expectedMRAs []reconcile.Request
	}{
		{
			name: "dedicated ClusterPermission with owner annotation",
			cp: createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
				createCRB("binding1", "user1", "view")),
			expectedMRAs: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-mra"}},
			},
		},
		{
			name: "ClusterPermission without owner annotation - no enqueue",
			cp: &cpv1alpha1.ClusterPermission{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "unmanaged-cp",
					Namespace: "cluster-a",
				},
			},
			expectedMRAs: []reconcile.Request{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue := &fakeWorkqueue{}
			handler := &clusterPermissionEventHandler{}

			handler.Create(context.Background(), event.TypedCreateEvent[client.Object]{
				Object: tt.cp,
			}, queue)

			if !areRequestsEqual(queue.items, tt.expectedMRAs) {
				t.Errorf("Create() enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, tt.expectedMRAs)
			}
		})
	}
}

func TestEventHandlers_Update_DedicatedCP(t *testing.T) {
	tests := []struct {
		name         string
		oldCP        client.Object
		newCP        client.Object
		expectedMRAs []reconcile.Request
	}{
		{
			name: "status change triggers owner reconciliation",
			oldCP: createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
				createCRB("binding1", "user1", "view")),
			newCP: func() *cpv1alpha1.ClusterPermission {
				cp := createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
					createCRB("binding1", "user1", "view"))
				cp.Status.Conditions = []metav1.Condition{
					{Type: "Applied", Status: metav1.ConditionTrue},
				}
				return cp
			}(),
			expectedMRAs: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-mra"}},
			},
		},
		{
			name: "spec change triggers owner reconciliation",
			oldCP: createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
				createCRB("binding1", "user1", "view")),
			newCP: createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
				createCRB("binding1", "user1", "edit")), // role changed
			expectedMRAs: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-mra"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue := &fakeWorkqueue{}
			handler := &clusterPermissionEventHandler{}

			handler.Update(context.Background(), event.TypedUpdateEvent[client.Object]{
				ObjectOld: tt.oldCP, ObjectNew: tt.newCP,
			}, queue)

			if !areRequestsEqual(queue.items, tt.expectedMRAs) {
				t.Errorf("Update() enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, tt.expectedMRAs)
			}
		})
	}
}

func TestEventHandlers_Delete_DedicatedCP(t *testing.T) {
	queue := &fakeWorkqueue{}
	handler := &clusterPermissionEventHandler{}

	cp := createDedicatedCP("mra-test-12345678", "cluster-a", "default/test-mra",
		createCRB("binding1", "user1", "view"))

	handler.Delete(context.Background(), event.TypedDeleteEvent[client.Object]{
		Object: cp,
	}, queue)

	expected := []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "test-mra"}},
	}

	if !areRequestsEqual(queue.items, expected) {
		t.Errorf("Delete() enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, expected)
	}
}

func TestEventHandlers_LegacyCP(t *testing.T) {
	t.Run("legacy ClusterPermission with per-binding owner annotations", func(t *testing.T) {
		queue := &fakeWorkqueue{}
		handler := &clusterPermissionEventHandler{}

		// Legacy shared ClusterPermission with per-binding owner annotations
		cp := createLegacyCP(
			createLegacyBinding("binding1", "", "default/mra1", "user1", "view"),
			createLegacyBinding("binding2", "", "default/mra2", "user2", "edit"),
		)

		handler.Create(context.Background(), event.TypedCreateEvent[client.Object]{
			Object: cp,
		}, queue)

		// Both MRAs should be enqueued
		expected := []reconcile.Request{
			{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra1"}},
			{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra2"}},
		}

		if !areRequestsEqual(queue.items, expected) {
			t.Errorf("Create() with legacy CP enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, expected)
		}
	})
}

func TestEnqueueMRA_InvalidIdentifier(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{name: "missing namespace", id: "mra1"},
		{name: "missing name", id: "ns/"},
		{name: "missing namespace 2", id: "/mra1"},
		{name: "empty", id: ""},
		{name: "too many parts", id: "default/mra/x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queue := &fakeWorkqueue{}
			enqueueMRA(context.Background(), tt.id, queue)
			if len(queue.items) != 0 {
				t.Errorf("should not enqueue invalid identifier %q, but got %d items", tt.id, len(queue.items))
			}
		})
	}
}

func TestRoleNameInValidationMessage(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		roleName string
		want     bool
	}{
		{
			name:     "single missing cluster role",
			message:  "The following cluster roles were not found: does-not-exist",
			roleName: "does-not-exist",
			want:     true,
		},
		{
			name:     "role in a list",
			message:  "The following cluster roles were not found: role-a, role-b, role-c",
			roleName: "role-b",
			want:     true,
		},
		{
			name:     "does not match substring of another role",
			message:  "The following cluster roles were not found: cluster-admin",
			roleName: "admin",
			want:     false,
		},
		{
			name:     "different role in the list",
			message:  "The following cluster roles were not found: does-not-exist, cluster-admin",
			roleName: "view",
			want:     false,
		},
		{
			name:     "empty role name",
			message:  "The following cluster roles were not found: view",
			roleName: "",
			want:     false,
		},
		{
			name:     "unrelated message",
			message:  "Apply manifest complete",
			roleName: "view",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := roleNameInValidationMessage(tt.message, tt.roleName)
			if got != tt.want {
				t.Errorf("roleNameInValidationMessage(%q, %q) = %v, want %v", tt.message, tt.roleName, got, tt.want)
			}
		})
	}
}

// createCRB creates a ClusterRoleBinding for testing
func createCRB(name, subjectName, roleName string) cpv1alpha1.ClusterRoleBinding {
	return cpv1alpha1.ClusterRoleBinding{
		Name:     name,
		Subjects: []rbacv1.Subject{{Kind: "User", Name: subjectName, APIGroup: rbacv1.GroupName}},
		RoleRef:  &rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName, APIGroup: rbacv1.GroupName},
	}
}

// createDedicatedCP creates a dedicated ClusterPermission (new model) with the MRA owner annotation
func createDedicatedCP(name, namespace, mraOwner string, bindings ...cpv1alpha1.ClusterRoleBinding) *cpv1alpha1.ClusterPermission {
	cp := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
			},
			Annotations: map[string]string{
				clusterPermissionMRAOwnerAnn: mraOwner,
			},
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{},
	}

	if len(bindings) > 0 {
		cp.Spec.ClusterRoleBindings = &bindings
	}

	return cp
}

// legacyBinding represents a binding in the legacy shared ClusterPermission model
type legacyBinding struct {
	bindingName string
	namespace   string
	mraOwner    string
	subjectName string
	roleName    string
}

func createLegacyBinding(bindingName, namespace, mraOwner, subjectName, roleName string) legacyBinding {
	return legacyBinding{bindingName, namespace, mraOwner, subjectName, roleName}
}

// createLegacyCP creates a legacy shared ClusterPermission with per-binding owner annotations
func createLegacyCP(bindings ...legacyBinding) *cpv1alpha1.ClusterPermission {
	cp := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      legacyClusterPermissionName,
			Namespace: "test-cluster",
			Labels: map[string]string{
				clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
			},
			Annotations: make(map[string]string),
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{},
	}

	var crbs []cpv1alpha1.ClusterRoleBinding
	var rbs []cpv1alpha1.RoleBinding

	for _, b := range bindings {
		if b.namespace != "" {
			rbs = append(rbs, cpv1alpha1.RoleBinding{
				Namespace: b.namespace,
				Name:      b.bindingName,
				Subjects:  []rbacv1.Subject{{Kind: "User", Name: b.subjectName, APIGroup: rbacv1.GroupName}},
				RoleRef:   cpv1alpha1.RoleRef{Kind: "ClusterRole", Name: b.roleName, APIGroup: rbacv1.GroupName},
			})
		} else {
			crbs = append(crbs, cpv1alpha1.ClusterRoleBinding{
				Name:     b.bindingName,
				Subjects: []rbacv1.Subject{{Kind: "User", Name: b.subjectName, APIGroup: rbacv1.GroupName}},
				RoleRef:  &rbacv1.RoleRef{Kind: "ClusterRole", Name: b.roleName, APIGroup: rbacv1.GroupName},
			})
		}
		// Legacy per-binding owner annotation
		cp.Annotations[legacyOwnerAnnotationPrefix+b.bindingName] = b.mraOwner
	}

	if len(crbs) > 0 {
		cp.Spec.ClusterRoleBindings = &crbs
	}
	if len(rbs) > 0 {
		cp.Spec.RoleBindings = &rbs
	}

	return cp
}

type fakeWorkqueue struct {
	items []reconcile.Request
}

func (f *fakeWorkqueue) Add(item reconcile.Request) {
	f.items = append(f.items, item)
}

func (f *fakeWorkqueue) AddAfter(item reconcile.Request, duration time.Duration) {
	f.items = append(f.items, item)
}

func (f *fakeWorkqueue) AddRateLimited(item reconcile.Request) {
	f.items = append(f.items, item)
}

func (f *fakeWorkqueue) Get() (item reconcile.Request, shutdown bool) {
	if len(f.items) == 0 {
		return reconcile.Request{}, true
	}
	item = f.items[0]
	f.items = f.items[1:]
	return item, false
}

func (f *fakeWorkqueue) Len() int {
	return len(f.items)
}

func (f *fakeWorkqueue) NumRequeues(item reconcile.Request) int {
	return 0
}

func (f *fakeWorkqueue) ShuttingDown() bool {
	return false
}

func (f *fakeWorkqueue) Done(item reconcile.Request)   {}
func (f *fakeWorkqueue) Forget(item reconcile.Request) {}
func (f *fakeWorkqueue) ShutDown()                     {}
func (f *fakeWorkqueue) ShutDownWithDrain()            {}

func areRequestsEqual(a, b []reconcile.Request) bool {
	if len(a) != len(b) {
		return false
	}

	aMap := make(map[types.NamespacedName]bool)
	bMap := make(map[types.NamespacedName]bool)

	for _, req := range a {
		aMap[req.NamespacedName] = true
	}
	for _, req := range b {
		bMap[req.NamespacedName] = true
	}

	return maps.Equal(aMap, bMap)
}
