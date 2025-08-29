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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
)

var _ = Describe("MulticlusterRoleAssignment Controller", func() {
	Context("When reconciling a resource", func() {
		const resourceName = "test-resource"

		ctx := context.Background()

		typeNamespacedName := types.NamespacedName{
			Name:      resourceName,
			Namespace: "default",
		}
		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}

		BeforeEach(func() {
			By("creating the custom resource for the Kind MulticlusterRoleAssignment")
			err := k8sClient.Get(ctx, typeNamespacedName, mra)
			if err != nil && errors.IsNotFound(err) {
				resource := &rbacv1alpha1.MulticlusterRoleAssignment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      resourceName,
						Namespace: "default",
					},
					Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
						Subject: rbacv1.Subject{
							Kind: "User",
							Name: "test-user",
						},
						RoleAssignments: []rbacv1alpha1.RoleAssignment{
							{
								Name:        "test-assignment",
								ClusterRole: "test-role",
								ClusterSets: []string{"test-cluster-set"},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, resource)).To(Succeed())
			}
		})

		AfterEach(func() {
			resource := &rbacv1alpha1.MulticlusterRoleAssignment{}
			err := k8sClient.Get(ctx, typeNamespacedName, resource)
			Expect(err).NotTo(HaveOccurred())

			By("Cleanup the specific resource instance MulticlusterRoleAssignment")
			Expect(k8sClient.Delete(ctx, resource)).To(Succeed())
		})
		It("should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			controllerReconciler := &MulticlusterRoleAssignmentReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}

			_, err := controllerReconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: typeNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			var updatedMRA rbacv1alpha1.MulticlusterRoleAssignment
			err = k8sClient.Get(ctx, typeNamespacedName, &updatedMRA)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, condition := range updatedMRA.Status.Conditions {
				if condition.Type == "Validated" {
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					Expect(condition.Reason).To(Equal("SpecIsValid"))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Validated condition status should be true")
		})
	})

	Context("Validation Logic", func() {
		var reconciler *MulticlusterRoleAssignmentReconciler

		BeforeEach(func() {
			reconciler = &MulticlusterRoleAssignmentReconciler{
				Client: k8sClient,
				Scheme: k8sClient.Scheme(),
			}
		})

		Describe("validateSpec", func() {
			It("should accept valid spec with unique role assignment names", func() {
				mra := &rbacv1alpha1.MulticlusterRoleAssignment{
					Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
						Subject: rbacv1.Subject{
							Kind: "User",
							Name: "test-user",
						},
						RoleAssignments: []rbacv1alpha1.RoleAssignment{
							{
								Name:        "assignment1",
								ClusterRole: "role1",
								ClusterSets: []string{"cluster-set1"},
							},
							{
								Name:        "assignment2",
								ClusterRole: "role2",
								ClusterSets: []string{"cluster-set2"},
							},
						},
					},
				}

				err := reconciler.validateSpec(mra)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject spec with duplicate role assignment names", func() {
				mra := &rbacv1alpha1.MulticlusterRoleAssignment{
					Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
						Subject: rbacv1.Subject{
							Kind: "User",
							Name: "test-user",
						},
						RoleAssignments: []rbacv1alpha1.RoleAssignment{
							{
								Name:        "duplicate-name",
								ClusterRole: "role1",
								ClusterSets: []string{"cluster-set1"},
							},
							{
								Name:        "duplicate-name",
								ClusterRole: "role2",
								ClusterSets: []string{"cluster-set2"},
							},
						},
					},
				}

				err := reconciler.validateSpec(mra)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("duplicate role assignment name found: duplicate-name"))
			})
		})
	})
})
