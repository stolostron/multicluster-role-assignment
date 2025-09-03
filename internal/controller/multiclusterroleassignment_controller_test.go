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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1beta2 "open-cluster-management.io/api/cluster/v1beta2"
)

var _ = Describe("MulticlusterRoleAssignment Controller", func() {
	ctx := context.Background()
	const multiclusterRoleAssignmentName = "test-multicluster-role-assignment"

	mraNamespacedName := types.NamespacedName{
		Name:      multiclusterRoleAssignmentName,
		Namespace: "default",
	}

	var mra *rbacv1alpha1.MulticlusterRoleAssignment

	const roleAssignment1Name = "test-assignment-1"
	const roleAssignment2Name = "test-assignment-2"

	const clusterSet1Name = "test-cluster-set-1"
	const clusterSet2Name = "test-cluster-set-2"

	var reconciler *MulticlusterRoleAssignmentReconciler

	BeforeEach(func() {
		reconciler = &MulticlusterRoleAssignmentReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		By("Creating the ManagedClusterSets")
		testClusterSet1 := &clusterv1beta2.ManagedClusterSet{
			ObjectMeta: metav1.ObjectMeta{Name: clusterSet1Name},
		}
		Expect(k8sClient.Create(ctx, testClusterSet1)).To(Succeed())

		testClusterSet2 := &clusterv1beta2.ManagedClusterSet{
			ObjectMeta: metav1.ObjectMeta{Name: clusterSet2Name},
		}
		Expect(k8sClient.Create(ctx, testClusterSet2)).To(Succeed())

		By("Creating the MulticlusterRoleAssignment")
		mra = &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      multiclusterRoleAssignmentName,
				Namespace: "default",
			},
			Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []rbacv1alpha1.RoleAssignment{
					{
						Name:        roleAssignment1Name,
						ClusterRole: "test-role",
						ClusterSets: []string{clusterSet1Name},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "test-role",
						ClusterSets: []string{clusterSet2Name},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, mra)).To(Succeed())
	})

	AfterEach(func() {
		By("Deleting the MulticlusterRoleAssignment")
		mra := &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mraNamespacedName.Name,
				Namespace: mraNamespacedName.Namespace,
			},
		}
		Expect(k8sClient.Delete(ctx, mra)).To(Succeed())

		By("Deleting the ManagedClusterSets")
		cs1 := &clusterv1beta2.ManagedClusterSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterSet1Name,
			},
		}
		Expect(k8sClient.Delete(ctx, cs1)).To(Succeed())

		cs2 := &clusterv1beta2.ManagedClusterSet{
			ObjectMeta: metav1.ObjectMeta{
				Name: clusterSet2Name,
			},
		}
		Expect(k8sClient.Delete(ctx, cs2)).To(Succeed())
	})

	Context("When reconciling a resource", func() {
		It("Should successfully reconcile the resource", func() {
			By("Reconciling the created resource")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Get(ctx, mraNamespacedName, mra)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, condition := range mra.Status.Conditions {
				if condition.Type == ConditionTypeValidated {
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					Expect(condition.Reason).To(Equal(ReasonSpecIsValid))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Validated condition status should be true")
		})

		It("Should set reason for missing cluster sets when reconciling with missing cluster sets", func() {
			mra.Spec.RoleAssignments[0].ClusterSets = []string{"non-existent-cluster-set"}
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())

			By("Reconciling with missing cluster sets")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("missing ManagedClusterSets"))

			err = k8sClient.Get(ctx, mraNamespacedName, mra)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, condition := range mra.Status.Conditions {
				if condition.Type == ConditionTypeValidated {
					Expect(condition.Status).To(Equal(metav1.ConditionFalse))
					Expect(condition.Reason).To(Equal(ReasonMissingClusterSets))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Validated condition should have ReasonMissingClusterSets")
		})

		It("Should set reason for invalid spec when reconciling with duplicate role assignment names", func() {
			mra.Spec.RoleAssignments[1].Name = mra.Spec.RoleAssignments[0].Name
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())

			By("Reconciling with duplicate role assignment names")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("duplicate role assignment name"))

			err = k8sClient.Get(ctx, mraNamespacedName, mra)
			Expect(err).NotTo(HaveOccurred())

			found := false
			for _, condition := range mra.Status.Conditions {
				if condition.Type == ConditionTypeValidated {
					Expect(condition.Status).To(Equal(metav1.ConditionFalse))
					Expect(condition.Reason).To(Equal(ReasonInvalidSpec))
					found = true
					break
				}
			}
			Expect(found).To(BeTrue(), "Validated condition should have ReasonInvalidSpec")
		})
	})

	Context("Validation Logic", func() {
		Describe("validateSpec", func() {
			It("Should validate spec with unique role assignment names and update status fields", func() {
				err := reconciler.validateSpec(ctx, mra)
				Expect(err).NotTo(HaveOccurred())

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))
				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StateTypePending))
					Expect(roleAssignmentStatus.Message).To(Equal(MessageManagedClusterSetValidationPassed))
				}
			})

			It("Should not validate spec with duplicate role assignment names", func() {
				// Create duplicate role assignment names
				mra.Spec.RoleAssignments[1].Name = mra.Spec.RoleAssignments[0].Name

				err := reconciler.validateSpec(ctx, mra)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("duplicate role assignment name found"))
			})

			It("Should not validate spec with non existent cluster set", func() {
				mra.Spec.RoleAssignments[0].ClusterSets = []string{"non-existent-cluster-set"}

				err := reconciler.validateSpec(ctx, mra)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("missing ManagedClusterSets"))
			})

			It("Should update role assignment status to failed for missing cluster sets", func() {
				mra.Spec.RoleAssignments[0].ClusterSets = []string{"missing-set1", "missing-set2"}
				mra.Spec.RoleAssignments[1].ClusterSets = []string{"missing-set1"}

				err := reconciler.validateSpec(ctx, mra)
				Expect(err).To(HaveOccurred())
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StateTypeError))
					Expect(roleAssignmentStatus.Message).To(ContainSubstring("Missing ManagedClusterSets"))
				}
			})
		})

		Describe("Status Management", func() {
			Describe("setCondition", func() {
				It("Should add new condition when not present", func() {
					reconciler.setCondition(mra, ConditionTypeReady, metav1.ConditionTrue, ReasonAllApplied,
						"All assignments applied")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.Type).To(Equal(ConditionTypeReady))
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					Expect(condition.Reason).To(Equal(ReasonAllApplied))
					Expect(condition.Message).To(Equal("All assignments applied"))
					Expect(condition.ObservedGeneration).To(Equal(mra.Generation))
				})

				It("Should update existing condition when status changes", func() {
					reconciler.setCondition(mra, ConditionTypeReady, metav1.ConditionTrue, ReasonAllApplied,
						"All assignments applied")
					reconciler.setCondition(mra, ConditionTypeReady, metav1.ConditionFalse, ReasonPartialFailure,
						"Some assignments failed")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.Type).To(Equal(ConditionTypeReady))
					Expect(condition.Status).To(Equal(metav1.ConditionFalse))
					Expect(condition.Reason).To(Equal(ReasonPartialFailure))
					Expect(condition.Message).To(Equal("Some assignments failed"))
				})

				It("Should only update ObservedGeneration when condition content is same", func() {
					reconciler.setCondition(mra, ConditionTypeReady, metav1.ConditionTrue, ReasonAllApplied,
						"All assignments applied")
					originalTime := mra.Status.Conditions[0].LastTransitionTime

					newGeneration := int64(2)
					mra.Generation = newGeneration
					reconciler.setCondition(mra, ConditionTypeReady, metav1.ConditionTrue, ReasonAllApplied,
						"All assignments applied")

					Expect(mra.Status.Conditions).To(HaveLen(1))
					condition := mra.Status.Conditions[0]
					Expect(condition.LastTransitionTime).To(Equal(originalTime))
					Expect(condition.ObservedGeneration).To(Equal(newGeneration))
				})
			})

			Describe("setRoleAssignmentStatus", func() {
				It("Should add new role assignment status when not present", func() {
					reconciler.setRoleAssignmentStatus(mra, "assignment1", StateTypeActive, "Successfully applied")

					Expect(mra.Status.RoleAssignments).To(HaveLen(1))
					status := mra.Status.RoleAssignments[0]
					Expect(status.Name).To(Equal("assignment1"))
					Expect(status.Status).To(Equal(StateTypeActive))
					Expect(status.Message).To(Equal("Successfully applied"))
				})

				It("Should update existing role assignment status", func() {
					reconciler.setRoleAssignmentStatus(mra, "assignment1", StateTypePending, "Initializing")
					reconciler.setRoleAssignmentStatus(mra, "assignment1", StateTypeActive, "Successfully applied")

					Expect(mra.Status.RoleAssignments).To(HaveLen(1))
					status := mra.Status.RoleAssignments[0]
					Expect(status.Name).To(Equal("assignment1"))
					Expect(status.Status).To(Equal(StateTypeActive))
					Expect(status.Message).To(Equal("Successfully applied"))
				})
			})

			Describe("initializeRoleAssignmentStatuses", func() {
				It("Should initialize status for all role assignments", func() {
					reconciler.initializeRoleAssignmentStatuses(mra)

					Expect(mra.Status.RoleAssignments).To(HaveLen(2))

					for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
						Expect(roleAssignmentStatus.Status).To(Equal(StateTypePending))
						Expect(roleAssignmentStatus.Message).To(Equal(MessageInitializingRoleAssignment))
					}
				})

				It("Should not duplicate or change existing role assignment statuses", func() {
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:    roleAssignment1Name,
							Status:  StateTypeActive,
							Message: "Already applied",
						},
					}

					reconciler.initializeRoleAssignmentStatuses(mra)

					Expect(mra.Status.RoleAssignments).To(HaveLen(2))

					for _, status := range mra.Status.RoleAssignments {
						Expect(status).NotTo(BeNil())

						switch status.Name {
						case roleAssignment1Name:
							Expect(status.Status).To(Equal(StateTypeActive))
							Expect(status.Message).To(Equal("Already applied"))
						case roleAssignment2Name:
							Expect(status.Status).To(Equal(StateTypePending))
							Expect(status.Message).To(Equal(MessageInitializingRoleAssignment))
						}
					}
				})
			})

			Describe("calculateReadyCondition", func() {
				BeforeEach(func() {
					mra.Status.Conditions = []metav1.Condition{
						{
							Type:   ConditionTypeValidated,
							Status: metav1.ConditionTrue,
						},
						{
							Type:   ConditionTypeApplied,
							Status: metav1.ConditionTrue,
						},
					}

					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
						{
							Name:   roleAssignment1Name,
							Status: StateTypeActive,
						},
						{
							Name:   roleAssignment2Name,
							Status: StateTypeActive,
						},
					}
				})

				It("Should return False when Validated condition is False", func() {
					mra.Status.Conditions[0].Status = metav1.ConditionFalse

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionFalse))
					Expect(reason).To(Equal(ReasonInvalidSpec))
					Expect(message).To(Equal(MessageSpecValidationFailed))
				})

				It("Should return False when any role assignment failed", func() {
					mra.Status.RoleAssignments[1].Status = StateTypeError

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionFalse))
					Expect(reason).To(Equal(ReasonPartialFailure))
					Expect(message).To(Equal(fmt.Sprintf("1 out of 2 %s", MessageRoleAssignmentsFailed)))
				})

				It("Should return Unknown when some role assignments are pending", func() {
					mra.Status.RoleAssignments[1].Status = StateTypePending
					mra.Status.Conditions = mra.Status.Conditions[:1] // Keep only Validated condition

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionUnknown))
					Expect(reason).To(Equal(ReasonInProgress))
					Expect(message).To(Equal(fmt.Sprintf("1 out of 2 %s", MessageRoleAssignmentsPending)))
				})

				It("Should return True when all role assignments are applied", func() {
					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionTrue))
					Expect(reason).To(Equal(ReasonAllApplied))
					Expect(message).To(Equal(fmt.Sprintf("2 out of 2 %s", MessageRoleAssignmentsAppliedSuccessfully)))
				})

				It("Should return Unknown when status cannot be determined", func() {
					mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{}

					status, reason, message := reconciler.calculateReadyCondition(mra)
					Expect(status).To(Equal(metav1.ConditionUnknown))
					Expect(reason).To(Equal(ReasonUnknown))
					Expect(message).To(Equal(MessageStatusCannotBeDetermined))
				})
			})
		})
	})
})
