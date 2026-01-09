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
	"slices"
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

func TestFindAffectedMRAs_Status(t *testing.T) {
	tests := []struct {
		name         string
		oldCP        *cpv1alpha1.ClusterPermission
		newCP        *cpv1alpha1.ClusterPermission
		expectedMRAs []string
	}{
		{
			name: "no changes - no MRAs should be affected",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			expectedMRAs: []string{},
		},
		{
			name: "status change - Clusterpermission status change of Condition Type",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Validation", metav1.ConditionTrue, "Reason", "Message")),
			),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name: "status change - Clusterpermission status change of Condition Status",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionFalse, "Reason", "Message")),
			),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name: "no changes - Clusterpermission status change of Condition Reason",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "ReasonChanged", "Message")),
			),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name: "no changes - Clusterpermission status change of condition Message",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "MessageChanged")),
			),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name:  "status added - should affect owner",
			oldCP: createCPStatus(), // Empty status
			newCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name: "status removed - should affect owner",
			oldCP: createCPStatus(
				createStatus("default/mra1", "default", "mra1", createCondition("Applied", metav1.ConditionTrue, "Reason", "Message")),
			),
			newCP:        createCPStatus(), // Empty status
			expectedMRAs: []string{"default/mra1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mras := findAffectedMRAs(tt.oldCP, tt.newCP)

			if len(mras) != len(tt.expectedMRAs) {
				t.Errorf("got %d affected MRAs, want %d\nGot: %v\nWant: %v",
					len(mras), len(tt.expectedMRAs), mras, tt.expectedMRAs)
			}

			// verifies all items exist
			for _, mra := range tt.expectedMRAs {
				if !mras[mra] {
					t.Errorf("expected MRA %q to be affected, but it wasn't\nAffected MRAs: %v", mra, mras)
				}
			}

			// verifies no unexpected items exist
			for mra := range mras {
				if !slices.Contains(tt.expectedMRAs, mra) {
					t.Errorf("unexpected MRA %q is affected\nExpected: %v\nGot: %v", mra, tt.expectedMRAs, mras)
				}
			}
		})
	}
}

func TestFindAffectedMRAs_Bindings(t *testing.T) {
	tests := []struct {
		name         string
		oldCP        *cpv1alpha1.ClusterPermission
		newCP        *cpv1alpha1.ClusterPermission
		expectedMRAs []string
	}{
		{
			name: "no changes - no MRAs should be affected",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view")),
			expectedMRAs: []string{},
		},
		{
			name: "binding added - only new owner affected",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "user2", "edit")),
			expectedMRAs: []string{"default/mra2"},
		},
		{
			name: "binding modified - selective reconciliation (1 of 3)",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "user2", "edit"),
				createBinding("administrator", "", "default/mra3", "user3", "admin")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "CHANGED", "view"),
				createBinding("editor", "", "default/mra2", "user2", "edit"),
				createBinding("administrator", "", "default/mra3", "user3", "admin")),
			expectedMRAs: []string{"default/mra1"},
		},
		{
			name: "binding removed - only removed owner affected",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "user2", "edit")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view")),
			expectedMRAs: []string{"default/mra2"},
		},
		{
			name: "multiple ClusterRoleBindings changed - multiple owners affected",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "user2", "edit"),
				createBinding("administrator", "", "default/mra3", "user3", "admin")),
			newCP: createCP(
				createBinding("CHANGED", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "CHANGED", "edit"),
				createBinding("administrator", "", "default/mra3", "user3", "CHANGED")),
			expectedMRAs: []string{"default/mra1", "default/mra2", "default/mra3"},
		},
		{
			name: "multiple RoleBinding modified - multiple owners affected",
			oldCP: createCP(
				createBinding("viewer", "ns1", "default/mra1", "user1", "view"),
				createBinding("editor", "ns2", "default/mra2", "user2", "edit"),
				createBinding("administrator", "ns3", "default/mra3", "user3", "admin"),
				createBinding("super-admin", "ns4", "default/mra4", "user4", "extra-admin"),
				createBinding("monitor", "ns5", "default/mra5", "user5", "mon")),
			newCP: createCP(
				createBinding("CHANGED", "ns1", "default/mra1", "user1", "view"),
				createBinding("editor", "CHANGED", "default/mra2", "user2", "edit"),
				createBinding("administrator", "ns3", "default/mra3", "CHANGED", "admin"),
				createBinding("super-admin", "ns4", "default/mra4", "user4", "CHANGED"),
				createBinding("monitor", "ns5", "default/mra5", "user5", "mon")),
			expectedMRAs: []string{"default/mra1", "default/mra2", "default/mra3", "default/mra4"},
		},
		{
			name: "orphaned binding - fallback to reconcile all owners",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "default-user", "view"),
				createBinding("editor", "", "default/mra2", "default-user", "edit")),
			newCP: func() *cpv1alpha1.ClusterPermission {
				result := createCP(
					createBinding("viewer", "", "default/mra1", "default-user", "view"),
					createBinding("editor", "", "default/mra2", "default-user", "edit"),
					createBinding("orphan", "", "default/orphan", "default-user", "view"))
				delete(result.Annotations, ownerAnnotationPrefix+"orphan")
				return result
			}(),
			expectedMRAs: []string{"default/mra1", "default/mra2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mras := findAffectedMRAs(tt.oldCP, tt.newCP)

			if len(mras) != len(tt.expectedMRAs) {
				t.Errorf("got %d affected MRAs, want %d\nGot: %v\nWant: %v",
					len(mras), len(tt.expectedMRAs), mras, tt.expectedMRAs)
			}

			for _, mra := range tt.expectedMRAs {
				if !mras[mra] {
					t.Errorf("expected MRA %q to be affected, but it wasn't\nAffected MRAs: %v", mra, mras)
				}
			}

			for mra := range mras {
				if !slices.Contains(tt.expectedMRAs, mra) {
					t.Errorf("unexpected MRA %q is affected\nExpected: %v\nGot: %v", mra, tt.expectedMRAs, mras)
				}
			}
		})
	}
}

func TestEventHandlers_Update(t *testing.T) {
	tests := []struct {
		name         string
		oldCP        client.Object
		newCP        client.Object
		expectedMRAs []reconcile.Request
	}{
		{
			name: "selective reconciliation - only affected MRA is enqueued",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "user1", "view"),
				createBinding("editor", "", "default/mra2", "default-user", "edit"),
				createBinding("administrator", "", "default/mra3", "default-user", "admin")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "CHANGED", "view"),
				createBinding("editor", "", "default/mra2", "default-user", "edit"),
				createBinding("administrator", "", "default/mra3", "default-user", "admin")),
			expectedMRAs: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra1"}},
			},
		},
		{
			name: "no changes - shouldn't be any reconciliations",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "default-user", "view")),
			newCP: createCP(
				createBinding("viewer", "", "default/mra1", "default-user", "view")),
			expectedMRAs: []reconcile.Request{},
		},
		{
			name: "orphaned binding - fallback enqueues all owners",
			oldCP: createCP(
				createBinding("viewer", "", "default/mra1", "default-user", "view"),
				createBinding("editor", "", "default/mra2", "default-user", "edit")),
			newCP: func() *cpv1alpha1.ClusterPermission {
				result := createCP(
					createBinding("viewer", "", "default/mra1", "default-user", "view"),
					createBinding("editor", "", "default/mra2", "default-user", "edit"),
					createBinding("orphan", "", "default/orphan", "default-user", "view"))
				delete(result.Annotations, ownerAnnotationPrefix+"orphan")
				return result
			}(),
			expectedMRAs: []reconcile.Request{
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra1"}},
				{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra2"}},
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

func TestEventHandlers_Create(t *testing.T) {
	queue := &fakeWorkqueue{}
	handler := &clusterPermissionEventHandler{}

	testCP := createCP(
		createBinding("viewer", "", "default/mra1", "default-user", "view"),
		createBinding("editor", "", "default/mra2", "default-user", "edit"))

	handler.Create(context.Background(), event.TypedCreateEvent[client.Object]{
		Object: testCP,
	}, queue)

	expected := []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra1"}},
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra2"}},
	}

	if !areRequestsEqual(queue.items, expected) {
		t.Errorf("Create() enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, expected)
	}
}

func TestEventHandlers_Delete(t *testing.T) {
	queue := &fakeWorkqueue{}
	handler := &clusterPermissionEventHandler{}

	testCP := createCP(
		createBinding("viewer", "", "default/mra1", "default-user", "view"),
		createBinding("editor", "", "default/mra2", "default-user", "edit"))

	handler.Delete(context.Background(), event.TypedDeleteEvent[client.Object]{
		Object: testCP,
	}, queue)

	expected := []reconcile.Request{
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra1"}},
		{NamespacedName: types.NamespacedName{Namespace: "default", Name: "mra2"}},
	}

	if !areRequestsEqual(queue.items, expected) {
		t.Errorf("Delete() enqueued incorrect requests\nGot:  %v\nWant: %v", queue.items, expected)
	}
}

func TestGeneral(t *testing.T) {
	t.Run("invalid MRA identifier format - validation", func(t *testing.T) {
		queue := &fakeWorkqueue{}

		invalid := []string{"mra1", "/mra1", "ns/", "", "default/mra/x"}

		for _, id := range invalid {
			enqueueMRA(context.Background(), id, queue)
			if len(queue.items) != 0 {
				t.Errorf("should not enqueue invalid identifier %q, but got %d items", id, len(queue.items))
				queue.items = nil
			}
		}
	})

	t.Run("orphaned ClusterRoleBinding detection", func(t *testing.T) {
		testCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test",
				Namespace:   "cluster1",
				Annotations: map[string]string{
					// No owner annotation for orphan binding
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{
				ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
					{
						Name:     "orphan",
						Subjects: []rbacv1.Subject{{Kind: "User", Name: "user", APIGroup: rbacv1.GroupName}},
						RoleRef:  &rbacv1.RoleRef{Kind: "ClusterRole", Name: "view", APIGroup: rbacv1.GroupName},
					},
				},
			},
		}

		crbMap := buildClusterRoleBindingMap(testCP)
		rbMap := buildRoleBindingMap(testCP)

		if !hasOrphanedBindings(testCP, crbMap, rbMap) {
			t.Error("should detect orphaned ClusterRoleBinding")
		}
	})

	t.Run("orphaned RoleBinding detection", func(t *testing.T) {
		testCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:        "test",
				Namespace:   "cluster1",
				Annotations: map[string]string{
					// No owner annotation for orphan RoleBinding
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{
				RoleBindings: &[]cpv1alpha1.RoleBinding{
					{
						Namespace: "default",
						Name:      "orphan",
						Subjects:  []rbacv1.Subject{{Kind: "User", Name: "user", APIGroup: rbacv1.GroupName}},
						RoleRef:   cpv1alpha1.RoleRef{Kind: "Role", Name: "view", APIGroup: rbacv1.GroupName},
					},
				},
			},
		}

		crbMap := buildClusterRoleBindingMap(testCP)
		rbMap := buildRoleBindingMap(testCP)

		if !hasOrphanedBindings(testCP, crbMap, rbMap) {
			t.Error("should detect orphaned RoleBinding")
		}
	})
}

// binding represents a single RBAC binding (ClusterRoleBinding or RoleBinding).
type binding struct {
	bindingName string
	namespace   string
	mraOwner    string
	subjectName string
	roleName    string
}

type status struct {
	mraOwner   string
	Namespace  string
	Name       string
	Conditions []metav1.Condition
}

func createStatus(mraOwner, namespace, name string, conditions ...metav1.Condition) status {
	return status{
		mraOwner:   mraOwner,
		Namespace:  namespace,
		Name:       name,
		Conditions: conditions,
	}
}

func createCondition(condType string, status metav1.ConditionStatus, reason, message string) metav1.Condition {
	return metav1.Condition{
		Type:    condType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}
}

// createBinding creates a binding. Pass empty string for namespace to create ClusterRoleBinding.
func createBinding(bindingName, namespace, mraOwner, subjectName, roleName string) binding {
	return binding{
		bindingName,
		namespace,
		mraOwner,
		subjectName,
		roleName,
	}
}

func createCPStatus(statuses ...status) *cpv1alpha1.ClusterPermission {
	cp := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mra-managed-permissions",
			Namespace:   "test-cluster",
			Annotations: make(map[string]string),
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{},
		Status: cpv1alpha1.ClusterPermissionStatus{
			ResourceStatus: &cpv1alpha1.ResourceStatus{},
		},
	}

	var crbs []cpv1alpha1.ClusterRoleBindingStatus
	var rbs []cpv1alpha1.RoleBindingStatus

	for _, s := range statuses {
		cp.Annotations[ownerAnnotationPrefix+s.Name] = s.mraOwner
		if s.Namespace != "" {
			rbs = append(rbs, cpv1alpha1.RoleBindingStatus{
				Name:       s.Name,
				Namespace:  s.Namespace,
				Conditions: s.Conditions,
			})
		} else {
			crbs = append(crbs, cpv1alpha1.ClusterRoleBindingStatus{
				Name:       s.Name,
				Conditions: s.Conditions,
			})
		}
	}

	if len(crbs) > 0 {
		cp.Status.ResourceStatus.ClusterRoleBindings = crbs
	}
	if len(rbs) > 0 {
		cp.Status.ResourceStatus.RoleBindings = rbs
	}

	return cp
}

// createCP creates a ClusterPermission with the specified bindings.
func createCP(bindings ...binding) *cpv1alpha1.ClusterPermission {
	cp := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "mra-managed-permissions",
			Namespace:   "test-cluster",
			Annotations: make(map[string]string),
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{},
	}

	var crbs []cpv1alpha1.ClusterRoleBinding
	var rbs []cpv1alpha1.RoleBinding

	for _, b := range bindings {
		if b.namespace != "" {
			// RoleBinding
			rbs = append(rbs, cpv1alpha1.RoleBinding{
				Namespace: b.namespace,
				Name:      b.bindingName,
				Subjects:  []rbacv1.Subject{{Kind: "User", Name: b.subjectName, APIGroup: rbacv1.GroupName}},
				RoleRef:   cpv1alpha1.RoleRef{Kind: "ClusterRole", Name: b.roleName, APIGroup: rbacv1.GroupName},
			})
			cp.Annotations[ownerAnnotationPrefix+b.bindingName] = b.mraOwner
		} else {
			// ClusterRoleBinding
			crbs = append(crbs, cpv1alpha1.ClusterRoleBinding{
				Name:     b.bindingName,
				Subjects: []rbacv1.Subject{{Kind: "User", Name: b.subjectName, APIGroup: rbacv1.GroupName}},
				RoleRef:  &rbacv1.RoleRef{Kind: "ClusterRole", Name: b.roleName, APIGroup: rbacv1.GroupName},
			})
			cp.Annotations[ownerAnnotationPrefix+b.bindingName] = b.mraOwner
		}
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
