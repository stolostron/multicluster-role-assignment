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
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
	clusterpermissionv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
)

var _ = Describe("MulticlusterRoleAssignment Controller", Ordered, func() {
	ctx := context.Background()
	const multiclusterRoleAssignmentName = "test-multicluster-role-assignment"
	const multiclusterRoleAssignmentNamespace = "open-cluster-management-global-set"

	mraNamespacedName := types.NamespacedName{
		Name:      multiclusterRoleAssignmentName,
		Namespace: multiclusterRoleAssignmentNamespace,
	}

	var mra *rbacv1alpha1.MulticlusterRoleAssignment
	var cp *clusterpermissionv1alpha1.ClusterPermission

	const roleAssignment1Name = "test-assignment-1"
	const roleAssignment2Name = "test-assignment-2"

	const cluster1Name = "test-cluster-1"
	const cluster2Name = "test-cluster-2"
	const cluster3Name = "test-cluster-3"

	var reconciler *MulticlusterRoleAssignmentReconciler

	BeforeAll(func() {
		reconciler = &MulticlusterRoleAssignmentReconciler{
			Client: k8sClient,
			Scheme: k8sClient.Scheme(),
		}

		By("Creating all test namespaces")
		allTestNamespaces := []string{multiclusterRoleAssignmentNamespace, cluster1Name, cluster2Name, cluster3Name}

		for _, namespaceName := range allTestNamespaces {
			testNamespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: namespaceName},
			}
			Expect(k8sClient.Create(ctx, testNamespace)).To(Succeed())
		}

		By("Creating all test ManagedClusters")
		clusterNames := []string{cluster1Name, cluster2Name, cluster3Name}
		for _, clusterName := range clusterNames {
			testCluster := &clusterv1.ManagedCluster{
				ObjectMeta: metav1.ObjectMeta{Name: clusterName},
			}
			Expect(k8sClient.Create(ctx, testCluster)).To(Succeed())
		}
	})

	BeforeEach(func() {
		By("Initializing the ClusterPermission")
		cp = &clusterpermissionv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      ClusterPermissionManagedName,
				Namespace: cluster2Name,
				Labels: map[string]string{
					ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
				},
			},
			Spec: clusterpermissionv1alpha1.ClusterPermissionSpec{},
		}

		By("Creating the MulticlusterRoleAssignment")
		mra = &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      multiclusterRoleAssignmentName,
				Namespace: multiclusterRoleAssignmentNamespace,
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
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{cluster1Name, cluster2Name},
						},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "test-role",
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{cluster3Name},
						},
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

		By("Deleting all ClusterPermissions")
		clusterNames := []string{cluster1Name, cluster2Name, cluster3Name}
		for _, clusterName := range clusterNames {
			cp := &clusterpermissionv1alpha1.ClusterPermission{
				ObjectMeta: metav1.ObjectMeta{
					Name:      ClusterPermissionManagedName,
					Namespace: clusterName,
				},
			}
			_ = k8sClient.Delete(ctx, cp)
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
				Expect(roleAssignmentStatus.Status).To(Equal(StatusTypeActive))
				Expect(roleAssignmentStatus.Reason).To(Equal(ReasonClusterPermissionApplied))
			}
		})

		It("Should set reason for missing clusters when reconciling with missing clusters", func() {
			mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{"non-existent-cluster"}
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

		It("Should complete full reconciliation including ClusterPermission creation", func() {
			mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())

			By("Reconciling the resource")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, mraNamespacedName, mra)).To(Succeed())

			By("Checking that ClusterPermission was created")
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      ClusterPermissionManagedName,
				Namespace: cluster1Name,
			}, cp)
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.Labels[ClusterPermissionManagedByLabel]).To(Equal(ClusterPermissionManagedByValue))

			By("Checking status conditions")
			validatedFound := false
			appliedFound := false
			readyFound := false

			for _, condition := range mra.Status.Conditions {
				switch condition.Type {
				case ConditionTypeValidated:
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					validatedFound = true
				case ConditionTypeApplied:
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					appliedFound = true
				case ConditionTypeReady:
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					readyFound = true
				}
			}

			Expect(validatedFound).To(BeTrue(), "Validated condition should be present")
			Expect(appliedFound).To(BeTrue(), "Applied condition should be present")
			Expect(readyFound).To(BeTrue(), "Ready condition should be present")

			By("Checking role assignment statuses")
			for _, status := range mra.Status.RoleAssignments {
				if status.Name == mra.Spec.RoleAssignments[0].Name {
					Expect(status.Status).To(Equal(StatusTypeActive))
				}
			}
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
					Expect(roleAssignmentStatus.Message).To(Equal(MessageInitializing))
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
						Expect(status.Message).To(Equal(MessageInitializing))
					}
				}
			})
		})

		Describe("clearStaleStatus", func() {
			BeforeEach(func() {
				mra.Generation = 2
				mra.Status.Conditions = []metav1.Condition{
					{
						Type:               ConditionTypeValidated,
						Status:             metav1.ConditionTrue,
						Reason:             ReasonSpecIsValid,
						Message:            MessageSpecValidationPassed,
						ObservedGeneration: 1,
					},
					{
						Type:               ConditionTypeApplied,
						Status:             metav1.ConditionTrue,
						Reason:             ReasonClusterPermissionApplied,
						Message:            MessageClusterPermissionApplied,
						ObservedGeneration: 1,
					},
					{
						Type:               ConditionTypeReady,
						Status:             metav1.ConditionTrue,
						Reason:             ReasonAllApplied,
						Message:            MessageRoleAssignmentsAppliedSuccessfully,
						ObservedGeneration: 1,
					},
				}
				mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  StatusTypeActive,
						Reason:  ReasonClusterPermissionApplied,
						Message: MessageClusterPermissionApplied,
					},
					{
						Name:    roleAssignment2Name,
						Status:  StatusTypeActive,
						Reason:  ReasonClusterPermissionApplied,
						Message: MessageClusterPermissionApplied,
					},
				}
			})

			It("Should reset Applied condition to Unknown status", func() {
				reconciler.clearStaleStatus(mra)

				var appliedCondition *metav1.Condition
				for i, condition := range mra.Status.Conditions {
					if condition.Type == ConditionTypeApplied {
						appliedCondition = &mra.Status.Conditions[i]
						break
					}
				}

				Expect(appliedCondition).NotTo(BeNil())
				Expect(appliedCondition.Status).To(Equal(metav1.ConditionUnknown))
				Expect(appliedCondition.Reason).To(Equal(ReasonApplyInProgress))
				Expect(appliedCondition.Message).To(Equal(MessageSpecChangedReEvaluating))
				Expect(appliedCondition.ObservedGeneration).To(Equal(mra.Generation))
			})

			It("Should not modify other conditions", func() {
				originalValidatedCondition := mra.Status.Conditions[0]
				originalReadyCondition := mra.Status.Conditions[2]

				reconciler.clearStaleStatus(mra)

				var newValidatedCondition, newReadyCondition *metav1.Condition
				for i, condition := range mra.Status.Conditions {
					switch condition.Type {
					case ConditionTypeValidated:
						newValidatedCondition = &mra.Status.Conditions[i]
					case ConditionTypeReady:
						newReadyCondition = &mra.Status.Conditions[i]
					}
				}

				Expect(newValidatedCondition.Status).To(Equal(originalValidatedCondition.Status))
				Expect(newValidatedCondition.Reason).To(Equal(originalValidatedCondition.Reason))
				Expect(newValidatedCondition.Message).To(Equal(originalValidatedCondition.Message))
				Expect(newValidatedCondition.ObservedGeneration).To(Equal(originalValidatedCondition.ObservedGeneration))

				Expect(newReadyCondition.Status).To(Equal(originalReadyCondition.Status))
				Expect(newReadyCondition.Reason).To(Equal(originalReadyCondition.Reason))
				Expect(newReadyCondition.Message).To(Equal(originalReadyCondition.Message))
				Expect(newReadyCondition.ObservedGeneration).To(Equal(originalReadyCondition.ObservedGeneration))
			})

			It("Should reset all role assignment statuses to Pending", func() {
				reconciler.clearStaleStatus(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))
				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(StatusTypePending))
					Expect(roleAssignmentStatus.Reason).To(Equal(ReasonInitializing))
					Expect(roleAssignmentStatus.Message).To(Equal(MessageInitializing))
				}
			})

			It("Should handle missing Applied condition gracefully", func() {
				mra.Status.Conditions = []metav1.Condition{
					{
						Type:               ConditionTypeValidated,
						Status:             metav1.ConditionTrue,
						Reason:             ReasonSpecIsValid,
						Message:            MessageSpecValidationPassed,
						ObservedGeneration: 1,
					},
				}

				Expect(func() {
					reconciler.clearStaleStatus(mra)
				}).NotTo(Panic())

				Expect(mra.Status.Conditions).To(HaveLen(1))
				Expect(mra.Status.Conditions[0].Type).To(Equal(ConditionTypeValidated))
			})

			It("Should handle empty role assignments gracefully", func() {
				mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{}

				Expect(func() {
					reconciler.clearStaleStatus(mra)
				}).NotTo(Panic())

				Expect(mra.Status.RoleAssignments).To(BeEmpty())
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

			It("Should return False when Applied condition is False", func() {
				mra.Status.Conditions[1].Status = metav1.ConditionFalse

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(ReasonApplyFailed))
				Expect(message).To(Equal(MessageClusterPermissionFailed))
			})

			It("Should return False when any role assignment failed", func() {
				mra.Status.RoleAssignments[1].Status = StatusTypeError

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(ReasonPartialFailure))
				Expect(message).To(Equal(fmt.Sprintf("1 out of 2 %s", MessageRoleAssignmentsFailed)))
			})

			It("Should return Pending when some role assignments are pending", func() {
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

		Describe("updateRoleAssignmentStatuses", func() {
			It("Should accumulate error messages for multi-cluster failures", func() {
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name, cluster2Name}
				reconciler.initializeRoleAssignmentStatuses(mra)

				state := &ClusterPermissionProcessingState{
					FailedClusters: map[string]error{
						cluster1Name: fmt.Errorf("connection timeout"),
						cluster2Name: fmt.Errorf("permission denied"),
					},
				}

				reconciler.updateRoleAssignmentStatuses(mra, []string{cluster1Name, cluster2Name}, state)

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(StatusTypeError))
						Expect(status.Reason).To(Equal(ReasonClusterPermissionFailed))
						Expect(status.Message).To(Equal(fmt.Sprintf(
							"Failed on 2/2 clusters: %s for cluster %s: %s; %s for cluster %s: %s",
							MessageClusterPermissionFailed, cluster1Name, "connection timeout",
							MessageClusterPermissionFailed, cluster2Name, "permission denied")))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Role assignment should have accumulated error messages")
			})

			It("Should preserve existing error status from cluster validation", func() {
				mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
					{
						Name:    mra.Spec.RoleAssignments[0].Name,
						Status:  StatusTypeError,
						Reason:  ReasonMissingClusters,
						Message: "Missing managed clusters: [missing-cluster]",
					},
				}

				state := &ClusterPermissionProcessingState{
					SuccessClusters: []string{cluster1Name},
				}

				reconciler.updateRoleAssignmentStatuses(mra, []string{cluster1Name}, state)

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(StatusTypeError))
						Expect(status.Reason).To(Equal(ReasonMissingClusters))
						Expect(status.Message).To(Equal("Missing managed clusters: [missing-cluster]"))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Existing error status should be preserved")
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
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{"non-existent-cluster", cluster1Name}

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
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{"missing-cluster1", "missing-cluster2"}
				mra.Spec.RoleAssignments[1].ClusterSelection.ClusterNames = []string{"missing-cluster1"}

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
		Describe("getClusterPermission", func() {
			It("Should return nil when ClusterPermission does not exist", func() {
				cp, err := reconciler.getClusterPermission(ctx, cluster2Name)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp).To(BeNil())
			})

			It("Should return error when ClusterPermission exists with name but missing management label", func() {
				cp.Labels = nil
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				cp, err := reconciler.getClusterPermission(ctx, cluster2Name)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("ClusterPermission found but not managed by this controller"))
				Expect(err.Error()).To(ContainSubstring(cluster2Name))
				Expect(err.Error()).To(ContainSubstring(ClusterPermissionManagedName))
				Expect(cp).To(BeNil())
			})

			It("Should return ClusterPermission when it exists and is managed", func() {
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				cp, err := reconciler.getClusterPermission(ctx, cluster2Name)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp).NotTo(BeNil())
				Expect(cp.Name).To(Equal(ClusterPermissionManagedName))
				Expect(cp.Namespace).To(Equal(cluster2Name))
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

		Describe("isRoleAssignmentTargetingCluster", func() {
			It("Should return true when cluster is in the list", func() {
				roleAssignment := rbacv1alpha1.RoleAssignment{
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{cluster1Name, cluster2Name},
					},
				}
				Expect(reconciler.isRoleAssignmentTargetingCluster(roleAssignment, cluster1Name)).To(BeTrue())
				Expect(reconciler.isRoleAssignmentTargetingCluster(roleAssignment, cluster2Name)).To(BeTrue())
			})

			It("Should return false when cluster is not in the list", func() {
				roleAssignment := rbacv1alpha1.RoleAssignment{
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{cluster1Name, cluster2Name},
					},
				}
				Expect(reconciler.isRoleAssignmentTargetingCluster(roleAssignment, cluster3Name)).To(BeFalse())
				Expect(reconciler.isRoleAssignmentTargetingCluster(roleAssignment, "non-existent")).To(BeFalse())
			})
		})

		Describe("ensureClusterPermissionAttempt", func() {
			It("Should create new ClusterPermission with MRA contributions", func() {
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster2Name}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      ClusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp.Labels[ClusterPermissionManagedByLabel]).To(Equal(ClusterPermissionManagedByValue))

				Expect(cp.Spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.ClusterRoleBindings).To(HaveLen(1))

				binding := (*cp.Spec.ClusterRoleBindings)[0]
				expectedBindingName := reconciler.generateBindingName(mra, "test-assignment-1")
				Expect(binding.Name).To(Equal(expectedBindingName))
				Expect(binding.RoleRef.Name).To(Equal("test-role"))
			})

			It("Should update existing ClusterPermission while preserving other MRA contributions", func() {
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "other-binding": "other-namespace/other-mra",
				}
				cp.Spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{
					{
						Name: "other-binding",
						RoleRef: &rbacv1.RoleRef{
							Kind:     ClusterRoleKind,
							Name:     "other-role",
							APIGroup: rbacv1.GroupName,
						},
						Subjects: []rbacv1.Subject{{Kind: "User", Name: "other-user"}},
					},
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster2Name}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      ClusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())

				Expect(cp.Spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.ClusterRoleBindings).To(HaveLen(2))

				Expect(cp.Annotations[OwnerAnnotationPrefix+"other-binding"]).To(Equal("other-namespace/other-mra"))
				expectedBindingName := reconciler.generateBindingName(mra, "test-assignment-1")
				expectedKey := reconciler.generateOwnerAnnotationKey(expectedBindingName)
				Expect(cp.Annotations[expectedKey]).To(Equal(fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)))
			})

			It("Should handle namespace scoped role assignments (RoleBindings)", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "edit"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster2Name}
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"namespace1", "namespace2"}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      ClusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())

				Expect(cp.Spec.ClusterRoleBindings).To(BeNil())
				Expect(cp.Spec.RoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.RoleBindings).To(HaveLen(2))

				expectedBindingName := reconciler.generateBindingName(mra, "namespaced-role")
				expectedKey1 := reconciler.generateOwnerAnnotationKey(fmt.Sprintf("%s-namespace1", expectedBindingName))
				expectedKey2 := reconciler.generateOwnerAnnotationKey(fmt.Sprintf("%s-namespace2", expectedBindingName))
				expectedValue := reconciler.generateMulticlusterRoleAssignmentIdentifier(mra)

				Expect(cp.Annotations[expectedKey1]).To(Equal(expectedValue))
				Expect(cp.Annotations[expectedKey2]).To(Equal(expectedValue))
			})

			It("Should fail when unmanaged ClusterPermission exists", func() {
				unmanagedCP := &clusterpermissionv1alpha1.ClusterPermission{
					ObjectMeta: metav1.ObjectMeta{
						Name:      ClusterPermissionManagedName,
						Namespace: cluster2Name,
					},
				}
				Expect(k8sClient.Create(ctx, unmanagedCP)).To(Succeed())

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not managed by this controller"))
			})
		})

		Describe("processClusterPermissions", func() {
			It("Should process ClusterPermissions and set Applied condition", func() {
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}

				reconciler.processClusterPermissions(ctx, mra, []string{cluster1Name})

				found := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == ConditionTypeApplied {
						Expect(condition.Status).To(Equal(metav1.ConditionTrue))
						Expect(condition.Reason).To(Equal(ReasonClusterPermissionApplied))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Applied condition should be set to True")
			})

			It("Should mark role assignments as Applied when successful", func() {
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
				reconciler.initializeRoleAssignmentStatuses(mra)

				reconciler.processClusterPermissions(ctx, mra, []string{cluster1Name})

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(StatusTypeActive))
						Expect(status.Reason).To(Equal(ReasonClusterPermissionApplied))
						Expect(status.Message).To(Equal(MessageClusterPermissionApplied))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Role assignment should be marked as Active")
			})

			It("Should handle ClusterPermission creation failures", func() {
				nonExistentCluster := "non-existent-cluster"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{nonExistentCluster}
				reconciler.initializeRoleAssignmentStatuses(mra)

				reconciler.processClusterPermissions(ctx, mra, []string{nonExistentCluster})

				appliedFound := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == ConditionTypeApplied {
						Expect(condition.Status).To(Equal(metav1.ConditionFalse))
						Expect(condition.Reason).To(Equal(ReasonClusterPermissionFailed))
						Expect(condition.Message).To(ContainSubstring(MessageClusterPermissionFailed))
						appliedFound = true
						break
					}
				}
				Expect(appliedFound).To(BeTrue(), "Applied condition should be set to False")

				roleAssignmentFound := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(StatusTypeError))
						Expect(status.Reason).To(Equal(ReasonClusterPermissionFailed))
						Expect(status.Message).To(ContainSubstring(MessageClusterPermissionFailed))
						Expect(status.Message).To(ContainSubstring(nonExistentCluster))
						roleAssignmentFound = true
						break
					}
				}
				Expect(roleAssignmentFound).To(BeTrue(), "Role assignment should be marked as Error")
			})

			It("Should handle mixed success and failure scenarios", func() {
				existingCluster := cluster1Name
				nonExistentCluster := "mixed-test-non-existent"

				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{existingCluster, nonExistentCluster}
				reconciler.initializeRoleAssignmentStatuses(mra)

				reconciler.processClusterPermissions(ctx, mra, []string{existingCluster, nonExistentCluster})

				appliedFound := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == ConditionTypeApplied {
						Expect(condition.Status).To(Equal(metav1.ConditionFalse))
						Expect(condition.Reason).To(Equal(ReasonClusterPermissionFailed))
						Expect(condition.Message).To(ContainSubstring("1 out of 2 clusters"))
						Expect(condition.Message).To(ContainSubstring(MessageClusterPermissionFailed))
						appliedFound = true
						break
					}
				}
				Expect(appliedFound).To(BeTrue(), "Applied condition should be set to False for partial failure")

				roleAssignmentFound := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(StatusTypeError))
						Expect(status.Reason).To(Equal(ReasonClusterPermissionFailed))
						Expect(status.Message).To(ContainSubstring(MessageClusterPermissionFailed))
						Expect(status.Message).To(ContainSubstring(nonExistentCluster))
						roleAssignmentFound = true
						break
					}
				}
				Expect(roleAssignmentFound).To(BeTrue(), "Role assignment should be marked as Error for mixed scenario")
			})
		})

		Describe("generateBindingName", func() {
			It("Should generate deterministic hash based binding names", func() {
				bindingName1 := reconciler.generateBindingName(mra, "test-role")
				bindingName2 := reconciler.generateBindingName(mra, "test-role")

				Expect(bindingName1).To(Equal(bindingName2))
				Expect(bindingName1).To(HavePrefix("mra-"))
				// Should be exactly 16 characters: "mra-" (4) + 12-char hash (12) = 16
				Expect(bindingName1).To(HaveLen(16))
			})

			It("Should generate different names for different inputs", func() {
				bindingName1 := reconciler.generateBindingName(mra, "admin-role")
				bindingName2 := reconciler.generateBindingName(mra, "viewer-role")

				Expect(bindingName1).NotTo(Equal(bindingName2))
				Expect(bindingName1).To(HavePrefix("mra-"))
				Expect(bindingName2).To(HavePrefix("mra-"))
			})

			It("Should generate different names for different MRAs", func() {
				otherMRA := &rbacv1alpha1.MulticlusterRoleAssignment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-mra",
						Namespace: "other-namespace",
					},
				}

				bindingName1 := reconciler.generateBindingName(mra, "test-role")
				bindingName2 := reconciler.generateBindingName(otherMRA, "test-role")

				Expect(bindingName1).NotTo(Equal(bindingName2))
			})
		})

		Describe("generateOwnerAnnotationKey", func() {
			It("Should generate correct annotation key with prefix", func() {
				bindingName := "mra-abcd1234efgh"
				key := reconciler.generateOwnerAnnotationKey(bindingName)
				expected := OwnerAnnotationPrefix + bindingName
				Expect(key).To(Equal(expected))
			})
		})

		Describe("generateMulticlusterRoleAssignmentIdentifier", func() {
			It("Should generate namespace/name identifier", func() {
				identifier := reconciler.generateMulticlusterRoleAssignmentIdentifier(mra)
				expected := fmt.Sprintf("%s/%s", mra.Namespace, mra.Name)
				Expect(identifier).To(Equal(expected))
			})
		})

		Describe("extractOwnedBindingNames", func() {
			It("Should extract owned binding names from annotations", func() {
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					OwnerAnnotationPrefix + "binding2": "other-namespace/other-mra",
					OwnerAnnotationPrefix + "binding3": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					"unrelated-annotation": "value",
				}

				ownedBindings := reconciler.extractOwnedBindingNames(cp, mra)
				Expect(ownedBindings).To(HaveLen(2))
				Expect(ownedBindings).To(ContainElements("binding1", "binding3"))
			})

			It("Should return empty list when no annotations exist", func() {
				cp.Annotations = nil

				ownedBindings := reconciler.extractOwnedBindingNames(cp, mra)
				Expect(ownedBindings).To(BeEmpty())
			})

			It("Should return empty list when no owned bindings exist", func() {
				cp.Annotations = map[string]string{
					"owner.rbac.open-cluster-management.io/binding1": "other-namespace/other-mra",
					"unrelated-annotation":                           "value",
				}

				ownedBindings := reconciler.extractOwnedBindingNames(cp, mra)
				Expect(ownedBindings).To(BeEmpty())
			})
		})

		Describe("calculateDesiredClusterPermissionSlice", func() {
			It("Should calculate cluster scoped (ClusterRoleBinding) permissions when no target namespaces", func() {
				mra.Spec.RoleAssignments[0].Name = "cluster-admin-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "cluster-admin"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
				mra.Spec.RoleAssignments[0].TargetNamespaces = nil

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(HaveLen(1))

				binding := slice.ClusterRoleBindings[0]
				expectedBindingName := reconciler.generateBindingName(mra, "cluster-admin-role")
				Expect(binding.Name).To(Equal(expectedBindingName))
				Expect(binding.RoleRef.Name).To(Equal("cluster-admin"))
				Expect(binding.Subjects).To(HaveLen(1))
				Expect(binding.Subjects[0].Name).To(Equal("test-user"))
			})

			It("Should calculate namespace scoped permissions (RoleBinding) when target namespaces specified", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role1"
				mra.Spec.RoleAssignments[0].ClusterRole = "admin"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"namespace1", "namespace2"}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.ClusterRoleBindings).To(BeEmpty())
				Expect(slice.RoleBindings).To(HaveLen(2))
				Expect(slice.OwnerAnnotations).To(HaveLen(2))

				for _, binding := range slice.RoleBindings {
					Expect(binding.RoleRef.Name).To(Equal("admin"))
					Expect(binding.Subjects).To(HaveLen(1))
					Expect(binding.Subjects[0].Name).To(Equal("test-user"))
					Expect([]string{"namespace1", "namespace2"}).To(ContainElement(binding.Namespace))
				}
			})

			It("Should return empty slice when role assignment does not target cluster", func() {
				mra.Spec.RoleAssignments[0].Name = "other-cluster-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "view"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster2Name} // Different cluster

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.ClusterRoleBindings).To(BeEmpty())
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(BeEmpty())
			})

			It("Should generate correct owner annotations for cluster-scoped permissions", func() {
				mra.Spec.RoleAssignments[0].Name = "cluster-admin-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "cluster-admin"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
				mra.Spec.RoleAssignments[0].TargetNamespaces = nil

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.OwnerAnnotations).To(HaveLen(1))

				expectedBindingName := reconciler.generateBindingName(mra, "cluster-admin-role")
				expectedAnnotationKey := OwnerAnnotationPrefix + expectedBindingName
				expectedMRAIdentifier := fmt.Sprintf("%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedAnnotationKey, expectedMRAIdentifier))
			})

			It("Should generate correct owner annotations for namespace scoped permissions", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role2"
				mra.Spec.RoleAssignments[0].ClusterRole = "edit"
				mra.Spec.RoleAssignments[0].ClusterSelection.ClusterNames = []string{cluster1Name}
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"ns1", "ns2"}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.OwnerAnnotations).To(HaveLen(2))

				baseBindingName := reconciler.generateBindingName(mra, "namespaced-role2")
				expectedMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				expectedKey1 := OwnerAnnotationPrefix + baseBindingName + "-ns1"
				expectedKey2 := OwnerAnnotationPrefix + baseBindingName + "-ns2"

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedKey1, expectedMRAIdentifier))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedKey2, expectedMRAIdentifier))
			})

			It("Should generate annotations for multiple role assignments targeting same cluster", func() {
				mra.Spec.RoleAssignments = []rbacv1alpha1.RoleAssignment{
					{
						Name:        "admin-role",
						ClusterRole: "cluster-admin",
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{cluster1Name},
						},
					},
					{
						Name:        "edit-role",
						ClusterRole: "edit",
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{cluster1Name},
						},
						TargetNamespaces: []string{"development"},
					},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings).To(HaveLen(1))
				Expect(slice.OwnerAnnotations).To(HaveLen(2))

				expectedMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				adminBindingName := reconciler.generateBindingName(mra, "admin-role")
				editBindingName := reconciler.generateBindingName(mra, "edit-role")

				expectedAdminKey := OwnerAnnotationPrefix + adminBindingName
				expectedEditKey := OwnerAnnotationPrefix + editBindingName + "-development"

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedAdminKey, expectedMRAIdentifier))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedEditKey, expectedMRAIdentifier))
			})
		})

		Describe("extractOthersClusterPermissionSlice", func() {
			It("Should extract bindings not owned by current MRA", func() {
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "cluster-role-binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					OwnerAnnotationPrefix + "cluster-role-binding2": "other-namespace/other-mra",
					OwnerAnnotationPrefix + "role-binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					OwnerAnnotationPrefix + "role-binding2": "other-namespace/other-mra",
					"unrelated-annotation":                  "value",
				}
				cp.Spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{
					{Name: "cluster-role-binding1"}, // Owned by current MRA
					{Name: "cluster-role-binding2"}, // Owned by other MRA
					{Name: "cluster-role-binding4"}, // Not in annotations (orphan, should get removed)
				}
				cp.Spec.RoleBindings = &[]clusterpermissionv1alpha1.RoleBinding{
					{Name: "role-binding1", Namespace: "ns1"}, // Owned by current MRA
					{Name: "role-binding2", Namespace: "ns2"}, // Owned by other MRA
				}

				slice := reconciler.extractOthersClusterPermissionSlice(cp, mra)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings).To(HaveLen(1))
				Expect(slice.OwnerAnnotations).To(HaveLen(3))

				var allBindingNames []string
				for _, binding := range slice.ClusterRoleBindings {
					allBindingNames = append(allBindingNames, binding.Name)
				}
				for _, binding := range slice.RoleBindings {
					allBindingNames = append(allBindingNames, binding.Name)
				}
				Expect(allBindingNames).To(ContainElements("cluster-role-binding2", "role-binding2"))
				Expect(allBindingNames).NotTo(ContainElements(
					"cluster-role-binding1", "cluster-role-binding4", "role-binding1"))
			})

			It("Should return empty slice when ClusterPermission is nil", func() {
				slice := reconciler.extractOthersClusterPermissionSlice(nil, mra)

				Expect(slice.ClusterRoleBindings).To(BeEmpty())
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(BeEmpty())
			})

			It("Should exclude orphaned bindings with no ownership annotations", func() {
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "tracked-binding": "other-namespace/other-mra",
					"unrelated-annotation":                    "value",
				}
				cp.Spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{
					{Name: "tracked-binding"},   // Has ownership annotation
					{Name: "orphaned-binding1"}, // No ownership annotation
					{Name: "orphaned-binding2"}, // No ownership annotation
				}
				cp.Spec.RoleBindings = &[]clusterpermissionv1alpha1.RoleBinding{
					{Name: "orphaned-role-binding"}, // No ownership annotation
				}

				slice := reconciler.extractOthersClusterPermissionSlice(cp, mra)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.ClusterRoleBindings[0].Name).To(Equal("tracked-binding"))
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(HaveLen(2))
			})

			It("Should preserve annotations from other MRAs while excluding current MRA annotations", func() {
				currentMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "current-binding1": currentMRAIdentifier,
					OwnerAnnotationPrefix + "current-binding2": currentMRAIdentifier,
					OwnerAnnotationPrefix + "other-binding1":   "other-namespace/other-mra1",
					OwnerAnnotationPrefix + "other-binding2":   "other-namespace/other-mra2",
					OwnerAnnotationPrefix + "other-binding3":   "other-namespace/other-mra3",
					"unrelated-annotation":                     "should-be-preserved",
					"another-unrelated":                        "also-preserved",
				}
				cp.Spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{
					{Name: "current-binding1"},
					{Name: "other-binding1"},
					{Name: "other-binding2"},
				}
				cp.Spec.RoleBindings = &[]clusterpermissionv1alpha1.RoleBinding{
					{Name: "current-binding2", Namespace: "ns1"},
					{Name: "other-binding3", Namespace: "ns2"},
				}

				slice := reconciler.extractOthersClusterPermissionSlice(cp, mra)

				Expect(slice.OwnerAnnotations).To(HaveLen(5))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					OwnerAnnotationPrefix+"other-binding1", "other-namespace/other-mra1"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					OwnerAnnotationPrefix+"other-binding2", "other-namespace/other-mra2"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					OwnerAnnotationPrefix+"other-binding3", "other-namespace/other-mra3"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("unrelated-annotation", "should-be-preserved"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("another-unrelated", "also-preserved"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "current-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "current-binding2"))
			})

			It("Should exclude orphaned annotations that have no corresponding bindings", func() {
				currentMRAIdentifier := fmt.Sprintf("%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)
				cp.Annotations = map[string]string{
					OwnerAnnotationPrefix + "current-binding1": currentMRAIdentifier,
					OwnerAnnotationPrefix + "current-binding2": currentMRAIdentifier,
					OwnerAnnotationPrefix + "other-binding1":   "other-namespace/other-mra",
					OwnerAnnotationPrefix + "other-binding2":   "other-namespace/other-mra",
					OwnerAnnotationPrefix + "missing-binding1": "other-namespace/other-mra",
					OwnerAnnotationPrefix + "missing-binding2": "other-namespace/other-mra3",
					"non-owner-annotation":                     "preserved",
				}
				cp.Spec.ClusterRoleBindings = &[]clusterpermissionv1alpha1.ClusterRoleBinding{
					{Name: "current-binding1"},
					{Name: "other-binding1"},
				}
				cp.Spec.RoleBindings = &[]clusterpermissionv1alpha1.RoleBinding{
					{Name: "current-binding2", Namespace: "ns1"},
					{Name: "other-binding2", Namespace: "ns2"},
				}

				slice := reconciler.extractOthersClusterPermissionSlice(cp, mra)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.ClusterRoleBindings[0].Name).To(Equal("other-binding1"))
				Expect(slice.RoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings[0].Name).To(Equal("other-binding2"))

				Expect(slice.OwnerAnnotations).To(HaveLen(3))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					OwnerAnnotationPrefix+"other-binding1", "other-namespace/other-mra"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					OwnerAnnotationPrefix+"other-binding2", "other-namespace/other-mra"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("non-owner-annotation", "preserved"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "missing-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "missing-binding2"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "current-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(OwnerAnnotationPrefix + "current-binding2"))
			})
		})

		Describe("mergeClusterPermissionSpecs", func() {
			It("Should merge ClusterRoleBindings from both slices", func() {
				others := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []clusterpermissionv1alpha1.ClusterRoleBinding{
						{Name: "other-binding1"},
						{Name: "other-binding2"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []clusterpermissionv1alpha1.ClusterRoleBinding{
						{Name: "desired-binding1"},
					},
				}

				spec := reconciler.mergeClusterPermissionSpecs(others, desired)

				Expect(spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*spec.ClusterRoleBindings).To(HaveLen(3))

				var bindingNames []string
				for _, binding := range *spec.ClusterRoleBindings {
					bindingNames = append(bindingNames, binding.Name)
				}
				Expect(bindingNames).To(ContainElements("other-binding1", "other-binding2", "desired-binding1"))
			})

			It("Should merge RoleBindings from both slices", func() {
				others := ClusterPermissionBindingSlice{
					RoleBindings: []clusterpermissionv1alpha1.RoleBinding{
						{Name: "other-role-binding1"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					RoleBindings: []clusterpermissionv1alpha1.RoleBinding{
						{Name: "desired-role-binding1"},
						{Name: "desired-role-binding2"},
					},
				}

				spec := reconciler.mergeClusterPermissionSpecs(others, desired)

				Expect(spec.RoleBindings).NotTo(BeNil())
				Expect(*spec.RoleBindings).To(HaveLen(3))
			})

			It("Should handle empty slices", func() {
				others := ClusterPermissionBindingSlice{}
				desired := ClusterPermissionBindingSlice{}

				spec := reconciler.mergeClusterPermissionSpecs(others, desired)

				Expect(spec.ClusterRoleBindings).To(BeNil())
				Expect(spec.RoleBindings).To(BeNil())
			})

			It("Should merge both ClusterRoleBindings and RoleBindings together", func() {
				others := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []clusterpermissionv1alpha1.ClusterRoleBinding{
						{Name: "other-cluster-binding1"},
						{Name: "other-cluster-binding2"},
					},
					RoleBindings: []clusterpermissionv1alpha1.RoleBinding{
						{Name: "other-role-binding1", Namespace: "ns1"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []clusterpermissionv1alpha1.ClusterRoleBinding{
						{Name: "desired-cluster-binding1"},
					},
					RoleBindings: []clusterpermissionv1alpha1.RoleBinding{
						{Name: "desired-role-binding1", Namespace: "ns2"},
						{Name: "desired-role-binding2", Namespace: "ns3"},
					},
				}

				spec := reconciler.mergeClusterPermissionSpecs(others, desired)

				Expect(spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*spec.ClusterRoleBindings).To(HaveLen(3))
				Expect(spec.RoleBindings).NotTo(BeNil())
				Expect(*spec.RoleBindings).To(HaveLen(3))

				var clusterBindingNames []string
				for _, binding := range *spec.ClusterRoleBindings {
					clusterBindingNames = append(clusterBindingNames, binding.Name)
				}
				Expect(clusterBindingNames).To(ContainElements(
					"other-cluster-binding1", "other-cluster-binding2", "desired-cluster-binding1"))

				var roleBindingNames []string
				for _, binding := range *spec.RoleBindings {
					roleBindingNames = append(roleBindingNames, binding.Name)
				}
				Expect(roleBindingNames).To(ContainElements(
					"other-role-binding1", "desired-role-binding1", "desired-role-binding2"))
			})
		})

		Describe("mergeClusterPermissionAnnotations", func() {
			It("Should merge annotations from both slices", func() {
				others := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						OwnerAnnotationPrefix + "binding1": "other/mra1",
						OwnerAnnotationPrefix + "binding2": "other/mra2",
						"unrelated-annotation":             "value",
					},
				}
				desired := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						OwnerAnnotationPrefix + "binding3": "current/mra",
						OwnerAnnotationPrefix + "binding4": "current/mra",
					},
				}

				annotations := reconciler.mergeClusterPermissionAnnotations(others, desired)

				Expect(annotations).To(HaveLen(5))
				Expect(annotations[OwnerAnnotationPrefix+"binding1"]).To(Equal("other/mra1"))
				Expect(annotations[OwnerAnnotationPrefix+"binding2"]).To(Equal("other/mra2"))
				Expect(annotations[OwnerAnnotationPrefix+"binding3"]).To(Equal("current/mra"))
				Expect(annotations[OwnerAnnotationPrefix+"binding4"]).To(Equal("current/mra"))
				Expect(annotations["unrelated-annotation"]).To(Equal("value"))
			})

			It("Should handle empty annotation maps", func() {
				others := ClusterPermissionBindingSlice{OwnerAnnotations: map[string]string{}}
				desired := ClusterPermissionBindingSlice{OwnerAnnotations: map[string]string{}}

				annotations := reconciler.mergeClusterPermissionAnnotations(others, desired)

				Expect(annotations).To(BeEmpty())
			})

			It("Should overwrite duplicate keys with desired values", func() {
				others := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						OwnerAnnotationPrefix + "binding1": "other/mra",
					},
				}
				desired := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						OwnerAnnotationPrefix + "binding1": "current/mra",
					},
				}

				annotations := reconciler.mergeClusterPermissionAnnotations(others, desired)

				Expect(annotations).To(HaveLen(1))
				Expect(annotations[OwnerAnnotationPrefix+"binding1"]).To(Equal("current/mra"))
			})
		})
	})
})
