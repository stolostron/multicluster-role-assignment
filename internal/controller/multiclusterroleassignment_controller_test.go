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

		Describe("Status Management", func() {
			var mra *rbacv1alpha1.MulticlusterRoleAssignment

			BeforeEach(func() {
				mra = &rbacv1alpha1.MulticlusterRoleAssignment{
					ObjectMeta: metav1.ObjectMeta{
						Generation: 1,
					},
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
			})

			Describe("setCondition", func() {
				It("should add new condition when not present", func() {
					reconciler.setCondition(mra, "Ready", metav1.ConditionTrue, "AllApplied", "All assignments applied")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.Type).To(Equal("Ready"))
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					Expect(condition.Reason).To(Equal("AllApplied"))
					Expect(condition.Message).To(Equal("All assignments applied"))
					Expect(condition.ObservedGeneration).To(Equal(mra.Generation))
				})

				It("should update existing condition when status changes", func() {
					reconciler.setCondition(mra, "Ready", metav1.ConditionTrue, "AllApplied", "All assignments applied")
					reconciler.setCondition(mra, "Ready", metav1.ConditionFalse, "PartialFailure", "Some assignments failed")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.Type).To(Equal("Ready"))
					Expect(condition.Status).To(Equal(metav1.ConditionFalse))
					Expect(condition.Reason).To(Equal("PartialFailure"))
					Expect(condition.Message).To(Equal("Some assignments failed"))
				})

				It("should only update ObservedGeneration when condition content is same", func() {
					reconciler.setCondition(mra, "Ready", metav1.ConditionTrue, "AllApplied", "All assignments applied")
					originalTime := mra.Status.Conditions[0].LastTransitionTime

					mra.Generation = 2
					reconciler.setCondition(mra, "Ready", metav1.ConditionTrue, "AllApplied", "All assignments applied")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.LastTransitionTime).To(Equal(originalTime))
					Expect(condition.ObservedGeneration).To(Equal(int64(2)))
				})
			})

			Describe("updateRoleAssignmentStatus", func() {
				It("should add new role assignment status when not present", func() {
					reconciler.setRoleAssignmentStatus(mra, "assignment1", "applied", "Successfully applied")

					Expect(mra.Status.RoleAssignments).To(HaveLen(1))
					status := mra.Status.RoleAssignments[0]
					Expect(status.Name).To(Equal("assignment1"))
					Expect(status.State).To(Equal("applied"))
					Expect(status.Message).To(Equal("Successfully applied"))
				})

				It("should update existing role assignment status", func() {
					reconciler.setRoleAssignmentStatus(mra, "assignment1", "pending", "Initializing")
					reconciler.setRoleAssignmentStatus(mra, "assignment1", "applied", "Successfully applied")

					Expect(mra.Status.RoleAssignments).To(HaveLen(1))
					status := mra.Status.RoleAssignments[0]
					Expect(status.Name).To(Equal("assignment1"))
					Expect(status.State).To(Equal("applied"))
					Expect(status.Message).To(Equal("Successfully applied"))
				})
			})

			Describe("initializeRoleAssignmentStatuses", func() {
				It("should initialize status for all role assignments", func() {
					reconciler.initializeRoleAssignmentStatuses(mra)

					Expect(mra.Status.RoleAssignments).To(HaveLen(2))

					var assignment1Status, assignment2Status *rbacv1alpha1.RoleAssignmentStatus
					for i, status := range mra.Status.RoleAssignments {
						switch status.Name {
						case "assignment1":
							assignment1Status = &mra.Status.RoleAssignments[i]
						case "assignment2":
							assignment2Status = &mra.Status.RoleAssignments[i]
						}
					}

					Expect(assignment1Status).NotTo(BeNil())
					Expect(assignment1Status.State).To(Equal("pending"))
					Expect(assignment1Status.Message).To(Equal("Initializing role assignment"))
					Expect(assignment2Status).NotTo(BeNil())
					Expect(assignment2Status.State).To(Equal("pending"))
					Expect(assignment2Status.Message).To(Equal("Initializing role assignment"))
				})

				It("should not duplicate or change existing role assignment statuses", func() {
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:    "assignment1",
							State:   "applied",
							Message: "Already applied",
						},
					}

					reconciler.initializeRoleAssignmentStatuses(mra)

					Expect(mra.Status.RoleAssignments).To(HaveLen(2))

					var assignment1Status, assignment2Status *rbacv1alpha1.RoleAssignmentStatus
					for i, status := range mra.Status.RoleAssignments {
						switch status.Name {
						case "assignment1":
							assignment1Status = &mra.Status.RoleAssignments[i]
						case "assignment2":
							assignment2Status = &mra.Status.RoleAssignments[i]
						}
					}

					Expect(assignment1Status).NotTo(BeNil())
					Expect(assignment1Status.State).To(Equal("applied"))
					Expect(assignment1Status.Message).To(Equal("Already applied"))
					Expect(assignment2Status).NotTo(BeNil())
					Expect(assignment2Status.State).To(Equal("pending"))
					Expect(assignment2Status.Message).To(Equal("Initializing role assignment"))
				})
			})

			Describe("calculateReadyCondition", func() {
				It("should return False when Validated condition is False", func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   "Validated",
							Status: metav1.ConditionFalse,
						},
					}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionFalse))
					Expect(reason).To(Equal("ValidationFailed"))
					Expect(message).To(Equal("Spec validation failed"))
				})

				It("should return False when any role assignment failed", func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   "Validated",
							Status: metav1.ConditionTrue,
						},
					}
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:  "assignment1",
							State: "applied",
						},
						{
							Name:  "assignment2",
							State: "failed",
						},
					}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionFalse))
					Expect(reason).To(Equal("PartialFailure"))
					Expect(message).To(Equal("1 out of 2 role assignments failed"))
				})

				It("should return False when Applied condition is False", func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   "Validated",
							Status: metav1.ConditionTrue,
						},
						{
							Type:   "Applied",
							Status: metav1.ConditionFalse,
						},
					}
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:  "assignment1",
							State: "applied",
						},
						{
							Name:  "assignment2",
							State: "applied",
						},
					}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionFalse))
					Expect(reason).To(Equal("ApplyFailed"))
					Expect(message).To(Equal("Failed to apply ClusterPermissions"))
				})

				It("should return Unknown when some role assignments are pending", func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   "Validated",
							Status: metav1.ConditionTrue,
						},
					}
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:  "assignment1",
							State: "applied",
						},
						{
							Name:  "assignment2",
							State: "pending",
						},
					}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionUnknown))
					Expect(reason).To(Equal("InProgress"))
					Expect(message).To(Equal("1 role assignments pending"))
				})

				It("should return True when all role assignments are applied", func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   "Validated",
							Status: metav1.ConditionTrue,
						},
						{
							Type:   "Applied",
							Status: metav1.ConditionTrue,
						},
					}
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:  "assignment1",
							State: "applied",
						},
						{
							Name:  "assignment2",
							State: "applied",
						},
					}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionTrue))
					Expect(reason).To(Equal("AllApplied"))
					Expect(message).To(Equal("All 2 role assignments applied successfully"))
				})

				It("should return Unknown when status cannot be determined", func() {
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionUnknown))
					Expect(reason).To(Equal("Unknown"))
					Expect(message).To(Equal("Status cannot be determined"))
				})
			})
		})
	})
})
