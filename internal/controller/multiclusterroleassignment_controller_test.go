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
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterpermissionv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
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

	const cluster1Name = "test-cluster-1"
	const cluster2Name = "test-cluster-2"
	const cluster3Name = "test-cluster-3"

	var reconciler *MulticlusterRoleAssignmentReconciler

	BeforeEach(func() {
		reconciler = &MulticlusterRoleAssignmentReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}
		By("Creating the ManagedClusters")
		clusterNames := []string{cluster1Name, cluster2Name, cluster3Name}
		for _, clusterName := range clusterNames {
			testCluster := &clusterv1.ManagedCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName},
			}
			Expect(k8sClient.Create(ctx, testCluster)).To(Succeed())
		}

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
						Clusters:    []string{cluster1Name, cluster2Name},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "test-role",
						Clusters:    []string{cluster3Name},
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

		By("Deleting the ManagedClusters")
		clusterNames := []string{cluster1Name, cluster2Name, cluster3Name}
		for _, clusterName := range clusterNames {
			cluster := &clusterv1.ManagedCluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterName,
				},
			}
			Expect(k8sClient.Delete(ctx, cluster)).To(Succeed())
		}
	})

	Context("When reconciling a resource", func() {
		It("Should successfully reconcile and set valid statuses", func() {
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

			Expect(mra.Status.RoleAssignments).To(HaveLen(2))
			for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
				Expect(roleAssignmentStatus.Status).To(Equal(StatusTypePending))
				Expect(roleAssignmentStatus.Reason).To(Equal(ReasonClustersValid))
				Expect(roleAssignmentStatus.Message).To(Equal(MessageClustersValid))
			}
		})

		It("Should set reason for missing clusters when reconciling with missing clusters", func() {
			mra.Spec.RoleAssignments[0].Clusters = []string{"non-existent-cluster"}
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())

			By("Reconciling with missing clusters")
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
			Expect(found).To(BeTrue(), "Validated condition should be True")

			Expect(mra.Status.RoleAssignments).To(HaveLen(2))
			errorFound := false
			for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
				if roleAssignmentStatus.Name == "test-assignment-1" {
					Expect(roleAssignmentStatus.Status).To(Equal(StatusTypeError))
					Expect(roleAssignmentStatus.Reason).To(Equal(ReasonMissingClusters))
					Expect(roleAssignmentStatus.Message).To(ContainSubstring(MessageMissingClusters))
					Expect(roleAssignmentStatus.Message).To(ContainSubstring("non-existent-cluster"))
					errorFound = true
					break
				}
			}
			Expect(errorFound).To(BeTrue(), "Role assignment should have error status for missing clusters")
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
			It("Should validate spec with unique role assignment names", func() {
				err := reconciler.validateSpec(mra)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should not validate spec with duplicate role assignment names", func() {
				// Create duplicate role assignment names
				mra.Spec.RoleAssignments[1].Name = mra.Spec.RoleAssignments[0].Name

				err := reconciler.validateSpec(mra)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("duplicate role assignment name found"))
			})
		})
	})

	Context("Status Management", func() {
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
				reconciler.setRoleAssignmentStatus(mra, "assignment1", StatusTypeActive, "TestReason",
					"Successfully applied")

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				status := mra.Status.RoleAssignments[0]
				Expect(status.Name).To(Equal("assignment1"))
				Expect(status.Status).To(Equal(StatusTypeActive))
				Expect(status.Reason).To(Equal("TestReason"))
				Expect(status.Message).To(Equal("Successfully applied"))
			})

			It("Should update existing role assignment status", func() {
				reconciler.setRoleAssignmentStatus(mra, "assignment1", StatusTypePending, "TestReasonPending",
					"Initializing")
				reconciler.setRoleAssignmentStatus(mra, "assignment1", StatusTypeActive, "TestReasonActive",
					"Successfully applied")

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				status := mra.Status.RoleAssignments[0]
				Expect(status.Name).To(Equal("assignment1"))
				Expect(status.Status).To(Equal(StatusTypeActive))
				Expect(status.Reason).To(Equal("TestReasonActive"))
				Expect(status.Message).To(Equal("Successfully applied"))
			})
		})

		Describe("initializeRoleAssignmentStatuses", func() {
			It("Should initialize status for all role assignments", func() {
				reconciler.initializeRoleAssignmentStatuses(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StatusTypePending))
					Expect(roleAssignmentStatus.Message).To(Equal(MessageInitializingRoleAssignment))
				}
			})

			It("Should not duplicate or change existing role assignment statuses", func() {
				mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  StatusTypeActive,
						Message: "Already applied",
					},
				}

				reconciler.initializeRoleAssignmentStatuses(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, status := range mra.Status.RoleAssignments {
					Expect(status).NotTo(BeNil())

					switch status.Name {
					case roleAssignment1Name:
						Expect(status.Status).To(Equal(StatusTypeActive))
						Expect(status.Message).To(Equal("Already applied"))
					case roleAssignment2Name:
						Expect(status.Status).To(Equal(StatusTypePending))
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
						Status: StatusTypeActive,
					},
					{
						Name:   roleAssignment2Name,
						Status: StatusTypeActive,
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
				mra.Status.RoleAssignments[1].Status = StatusTypeError

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(ReasonPartialFailure))
				Expect(message).To(Equal(fmt.Sprintf("1 out of 2 %s", MessageRoleAssignmentsFailed)))
			})

			It("Should return Unknown when some role assignments are pending", func() {
				mra.Status.RoleAssignments[1].Status = StatusTypePending
				mra.Status.Conditions = mra.Status.Conditions[:1] // Keep only Validated condition

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
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

	Context("Cluster Aggregation Tests", func() {
		Describe("aggregateClusters", func() {
			It("Should aggregate clusters from role assignments", func() {
				clusters, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(3))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name, cluster3Name))
			})

			It("Should update role assignment statuses during aggregation", func() {
				_, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).NotTo(HaveOccurred())
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StatusTypePending))
					Expect(roleAssignmentStatus.Reason).To(Equal(ReasonClustersValid))
					Expect(roleAssignmentStatus.Message).To(Equal(MessageClustersValid))
				}
			})

			It("Should handle missing clusters gracefully", func() {
				mra.Spec.RoleAssignments[0].Clusters = []string{"non-existent-cluster", cluster1Name}

				clusters, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(ContainElements(cluster1Name))
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				roleAssignmentStatus := mra.Status.RoleAssignments[0]
				Expect(roleAssignmentStatus.Status).To(Equal(StatusTypeError))
				Expect(roleAssignmentStatus.Reason).To(Equal(ReasonMissingClusters))
				Expect(roleAssignmentStatus.Message).To(ContainSubstring(MessageMissingClusters))
			})

			It("Should update role assignment status to failed for missing clusters", func() {
				mra.Spec.RoleAssignments[0].Clusters = []string{"missing-cluster1", "missing-cluster2"}
				mra.Spec.RoleAssignments[1].Clusters = []string{"missing-cluster1"}

				clusters, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(BeEmpty())
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StatusTypeError))
					Expect(roleAssignmentStatus.Message).To(ContainSubstring(MessageMissingClusters))
					switch roleAssignmentStatus.Name {
					case roleAssignment1Name:
						Expect(roleAssignmentStatus.Message).To(ContainSubstring("missing-cluster1"))
						Expect(roleAssignmentStatus.Message).To(ContainSubstring("missing-cluster2"))
					case roleAssignment2Name:
						Expect(roleAssignmentStatus.Message).To(ContainSubstring("missing-cluster1"))
						Expect(roleAssignmentStatus.Message).NotTo(ContainSubstring("missing-cluster2"))
					}
				}
			})
		})
	})

	Context("ClusterPermission Operations", func() {
		const testClusterNamespace = "default"
		var cp *clusterpermissionv1alpha1.ClusterPermission

		BeforeEach(func() {
			cp = &clusterpermissionv1alpha1.ClusterPermission{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ClusterPermissionManagedName,
					Namespace: testClusterNamespace,
					Labels: map[string]string{
						ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
					},
				},
			}
		})

		AfterEach(func() {
			_ = k8sClient.Delete(ctx, cp)
		})

		Describe("getClusterPermission", func() {
			It("Should return nil when ClusterPermission does not exist", func() {
				cp, err := reconciler.getClusterPermission(ctx, testClusterNamespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp).To(BeNil())
			})

			It("Should return error when ClusterPermission exists with name but missing management label", func() {
				cp.Labels = nil
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				cp, err := reconciler.getClusterPermission(ctx, testClusterNamespace)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("ClusterPermission found but not managed by this controller"))
				Expect(err.Error()).To(ContainSubstring(testClusterNamespace))
				Expect(err.Error()).To(ContainSubstring(ClusterPermissionManagedName))
				Expect(cp).To(BeNil())
			})

			It("Should return ClusterPermission when it exists and is managed", func() {
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				cp, err := reconciler.getClusterPermission(ctx, testClusterNamespace)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp).NotTo(BeNil())
				Expect(cp.Name).To(Equal(ClusterPermissionManagedName))
				Expect(cp.Namespace).To(Equal(testClusterNamespace))
			})
		})

		Describe("isClusterPermissionManaged", func() {
			It("Should return false when labels are nil", func() {
				cp.Labels = nil
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeFalse())
			})

			It("Should return false when management label is missing", func() {
				cp.Labels = map[string]string{
					"other-label": "value",
				}
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeFalse())
			})

			It("Should return false when management label has wrong value", func() {
				cp.Labels = map[string]string{
					ClusterPermissionManagedByLabel: "wrong-value",
				}
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeFalse())
			})

			It("Should return true when management label is correct", func() {
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeTrue())
			})
		})
	})
})
