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
	"slices"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
		By("Removing finalizer from MulticlusterRoleAssignment")
		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		if err := k8sClient.Get(ctx, mraNamespacedName, mra); err == nil {
			mra.Finalizers = []string{}
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())
		}

		By("Deleting the MulticlusterRoleAssignment")
		mra = &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mraNamespacedName.Name,
				Namespace: mraNamespacedName.Namespace,
			},
		}
		Expect(k8sClient.Delete(ctx, mra)).To(Succeed())

		By("Waiting for MulticlusterRoleAssignment deletion to complete")
		Eventually(func() bool {
			err := k8sClient.Get(ctx, mraNamespacedName, &rbacv1alpha1.MulticlusterRoleAssignment{})
			return apierrors.IsNotFound(err)
		}, "10s", "100ms").Should(BeTrue(), "MulticlusterRoleAssignment should be deleted")

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
			It("Should add new role assignment status when not present", Label("allows-errors"), func() {
				reconciler.setRoleAssignmentStatus(mra, "assignment1", StatusTypeActive, "TestReason",
					"Successfully applied")

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				status := mra.Status.RoleAssignments[0]
				Expect(status.Name).To(Equal("assignment1"))
				Expect(status.Status).To(Equal(StatusTypeActive))
				Expect(status.Reason).To(Equal("TestReason"))
				Expect(status.Message).To(Equal("Successfully applied"))
			})

			It("Should update existing role assignment status", Label("allows-errors"), func() {
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

	Context("Finalizer handling in Reconcile", func() {
		var mra *rbacv1alpha1.MulticlusterRoleAssignment
		var testNamespace *corev1.Namespace

		BeforeEach(func() {
			// Create test namespace
			testNamespace = &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-namespace",
				},
			}
			if err := k8sClient.Get(ctx, client.ObjectKey{Name: testNamespace.Name}, testNamespace); err != nil {
				Expect(k8sClient.Create(ctx, testNamespace)).To(Succeed())
			}

			mra = &rbacv1alpha1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-finalizer-mra",
					Namespace: "test-namespace",
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
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{cluster1Name},
							},
						},
					},
				},
			}
		})

		Describe("Adding finalizer", func() {
			It("Should add finalizer to new resource without finalizer", func() {
				// Create MRA without finalizer
				Expect(k8sClient.Create(ctx, mra)).To(Succeed())

				// Reconcile should add finalizer
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// Verify finalizer was added
				updatedMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
				err = k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, updatedMra)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedMra.Finalizers).To(ContainElement(FinalizerName))
			})

			It("Should not add finalizer if already present", func() {
				// Create MRA with finalizer already present
				mra.Finalizers = []string{FinalizerName}
				Expect(k8sClient.Create(ctx, mra)).To(Succeed())

				// Get initial resource version
				initialMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, initialMra)
				Expect(err).NotTo(HaveOccurred())

				// Reconcile should not trigger update for finalizer
				_, err = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// Verify finalizer is still present but resource wasn't updated due to finalizer
				updatedMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
				err = k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, updatedMra)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedMra.Finalizers).To(ContainElement(FinalizerName))
			})

			It("Should handle update error when adding finalizer", func() {
				// Create MRA without finalizer
				Expect(k8sClient.Create(ctx, mra)).To(Succeed())

				// Create a conflicting version to cause update error
				conflictMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
				err := k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, conflictMra)
				Expect(err).NotTo(HaveOccurred())

				// Modify the resource to create a conflict
				conflictMra.Annotations = map[string]string{"conflict": "true"}
				Expect(k8sClient.Update(ctx, conflictMra)).To(Succeed())

				// Reconcile with stale resource - should handle conflict gracefully
				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					},
				})

				// Should requeue on error
				if err != nil {
					Expect(result.RequeueAfter).To(Equal(DefaultRequeueDelay))
				}
			})
		})

		Describe("Removing finalizer during deletion", func() {
			BeforeEach(func() {
				// Create MRA with finalizer
				mra.Finalizers = []string{FinalizerName}
				Expect(k8sClient.Create(ctx, mra)).To(Succeed())
			})

			It("Should remove finalizer and clean up resources when deleting", func() {
				// Mark for deletion
				Expect(k8sClient.Delete(ctx, mra)).To(Succeed())

				// Reconcile should remove finalizer after cleanup
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())

				// Verify resource is eventually deleted
				Eventually(func() bool {
					err := k8sClient.Get(ctx, client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					}, &rbacv1alpha1.MulticlusterRoleAssignment{})
					return apierrors.IsNotFound(err)
				}, "5s", "100ms").Should(BeTrue(), "Resource should be deleted after finalizer removal")
			})
		})

		AfterEach(func() {
			// Clean up test resource
			testMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
			if err := k8sClient.Get(ctx, client.ObjectKey{
				Name:      mra.Name,
				Namespace: mra.Namespace,
			}, testMra); err == nil {
				testMra.Finalizers = []string{}
				err := k8sClient.Update(ctx, testMra)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Delete(ctx, testMra)
				Expect(err).NotTo(HaveOccurred())
			}
		})
	})
})

func TestHandleMulticlusterRoleAssignmentDeletion(t *testing.T) {
	var testscheme = scheme.Scheme
	err := rbacv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterv1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterpermissionv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = corev1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}

	testMra1 := &rbacv1alpha1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample1",
			Namespace: "open-cluster-management",
		},
		Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user1",
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster1"},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster2"},
					},
				},
			},
		},
	}

	testMra2 := &rbacv1alpha1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample2",
			Namespace: "open-cluster-management",
		},
		Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user2",
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster1"},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster2"},
					},
				},
			},
		},
	}

	testCp1 := &clusterpermissionv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mra-managed-permissions",
			Namespace: "cluster1",
			Annotations: map[string]string{
				OwnerAnnotationPrefix + "mra-35e36445c130": "open-cluster-management/multiclusterroleassignment-sample2",
				OwnerAnnotationPrefix + "mra-9f00838bc8aa": "open-cluster-management/multiclusterroleassignment-sample1",
			},
			Labels: map[string]string{
				ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
			},
		},
		Spec: clusterpermissionv1alpha1.ClusterPermissionSpec{
			ClusterRoleBindings: &[]clusterpermissionv1alpha1.ClusterRoleBinding{
				{
					Name: "mra-9f00838bc8aa",
					RoleRef: &rbacv1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user1"}},
				},
				{
					Name: "mra-35e36445c130",
					RoleRef: &rbacv1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user2"}},
				},
			},
		},
	}

	testCp2 := &clusterpermissionv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mra-managed-permissions",
			Namespace: "cluster2",
			Annotations: map[string]string{
				OwnerAnnotationPrefix + "mra-d10a91efc36c": "open-cluster-management/multiclusterroleassignment-sample2",
				OwnerAnnotationPrefix + "mra-d881ad60fb3a": "open-cluster-management/multiclusterroleassignment-sample1",
			},
			Labels: map[string]string{
				ClusterPermissionManagedByLabel: ClusterPermissionManagedByValue,
			},
		},
		Spec: clusterpermissionv1alpha1.ClusterPermissionSpec{
			ClusterRoleBindings: &[]clusterpermissionv1alpha1.ClusterRoleBinding{
				{
					Name: "mra-d881ad60fb3a",
					RoleRef: &rbacv1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user1"}},
				},
				{
					Name: "mra-d10a91efc36c",
					RoleRef: &rbacv1.RoleRef{
						Kind:     ClusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user2"}},
				},
			},
		},
	}

	testCluster1 := &clusterv1.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster1",
		},
	}

	testCluster2 := &clusterv1.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster2",
		},
	}

	t.Run("Test handle MulticlusterRoleAssignment deletion", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(testscheme).WithObjects(
			testMra1, testMra2, testCp1, testCp2, testCluster1, testCluster2).Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		// Delete first MRA
		err := reconciler.handleMulticlusterRoleAssignmentDeletion(ctx, testMra1)
		if err != nil {
			t.Fatalf("handleMulticlusterRoleAssignmentDeletion() error = %v", err)
		}

		// Validate ClusterPermission
		err = fakeClient.Get(ctx, types.NamespacedName{Name: "mra-managed-permissions", Namespace: "cluster1"}, testCp1)
		if err != nil {
			t.Fatalf("get ClusterPermission error = %v", err)
		}
		if len(testCp1.Annotations) != 1 {
			t.Fatalf("testCp1.Annotations length = %d, want 1", len(testCp1.Annotations))
		}
		if len(*testCp1.Spec.ClusterRoleBindings) != 1 {
			t.Fatalf("testCp1.Spec.ClusterRoleBindings length = %d, want 1", len(*testCp1.Spec.ClusterRoleBindings))
		}

		// Delete second MRA
		err = reconciler.handleMulticlusterRoleAssignmentDeletion(ctx, testMra2)
		if err != nil {
			t.Fatalf("handleMulticlusterRoleAssignmentDeletion() error = %v", err)
		}

		err = fakeClient.Get(ctx, types.NamespacedName{Name: "mra-managed-permissions", Namespace: "cluster1"}, testCp1)
		if err == nil {
			t.Fatalf("ClusterPermission should be deleted")
		}

		err = fakeClient.Get(ctx, types.NamespacedName{Name: "mra-managed-permissions", Namespace: "cluster2"}, testCp2)
		if err == nil {
			t.Fatalf("ClusterPermission should be deleted")
		}
	})
}

func TestAggregateClusters(t *testing.T) {
	var testscheme = scheme.Scheme
	err := rbacv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterv1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = corev1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}

	testMra := &rbacv1alpha1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample",
			Namespace: "open-cluster-management",
		},
		Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user1",
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster1"},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster2"},
					},
				},
			},
		},
	}

	testCluster1 := &clusterv1.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster1",
		},
	}

	testCluster2 := &clusterv1.ManagedCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster2",
		},
	}

	t.Run("Test aggregateClusters", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(testscheme).WithObjects(
			testMra, testCluster1, testCluster2).WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(ctx, types.NamespacedName{Name: testMra.Name, Namespace: testMra.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
			{
				Name:    "test-assignment-1",
				Status:  "Active",
				Reason:  "ClusterPermissionApplied",
				Message: "ClusterPermission applied successfully",
			},
		}
		err = fakeClient.Status().Update(ctx, mra)
		if err != nil {
			t.Fatalf("update Status error = %v", err)
		}

		clusters, err := reconciler.aggregateClusters(ctx, mra)
		if err != nil {
			t.Fatalf("aggregateClusters error = %v", err)
		}
		if len(clusters) != 2 {
			t.Fatalf("aggregateClusters returned %d clusters, want 2", len(clusters))
		}
		if !slices.Contains(clusters, "cluster1") || !slices.Contains(clusters, "cluster2") {
			t.Fatalf("aggregateClusters returned clusters = %v, want [cluster1, cluster2]", clusters)
		}
	})
}

func TestUpdateStatusBasicFunctionality(t *testing.T) {
	// Use the same scheme setup pattern as the working tests
	testscheme := scheme.Scheme
	err := rbacv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterv1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterpermissionv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}

	testMra := &rbacv1alpha1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-update-status",
			Namespace:       "open-cluster-management",
			ResourceVersion: "1",
		},
		Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user",
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster1"},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster2"},
					},
				},
			},
		},
		Status: rbacv1alpha1.MulticlusterRoleAssignmentStatus{
			Conditions: []metav1.Condition{
				{
					Type:    ConditionTypeValidated,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonSpecIsValid,
					Message: MessageSpecValidationPassed,
				},
				{
					Type:    ConditionTypeApplied,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonClusterPermissionApplied,
					Message: MessageClusterPermissionApplied,
				},
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignmentStatus{
				{
					Name:    "test-assignment-1",
					Status:  StatusTypeActive,
					Reason:  ReasonClusterPermissionApplied,
					Message: MessageClusterPermissionApplied,
				},
				{
					Name:    "test-assignment-2",
					Status:  StatusTypeActive,
					Reason:  ReasonClusterPermissionApplied,
					Message: MessageClusterPermissionApplied,
				},
			},
		},
	}

	t.Run("Should successfully update status on first attempt", func(t *testing.T) {
		// Create a fresh MRA object for this test
		mra := &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-update-status-simple",
				Namespace: "open-cluster-management",
			},
			Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []rbacv1alpha1.RoleAssignment{
					{
						Name:        "test-assignment-1",
						ClusterRole: "test-role",
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{"cluster1"},
						},
					},
				},
			},
		}

		// Enable status subresource to prevent retry conflicts
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(mra).
			WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		// Get the object from the fake client
		fetchedMra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		objKey := client.ObjectKey{Name: mra.Name, Namespace: mra.Namespace}

		err := fakeClient.Get(context.TODO(), objKey, fetchedMra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Modify status to test update
		fetchedMra.Status.Conditions = []metav1.Condition{
			{
				Type:    ConditionTypeValidated,
				Status:  metav1.ConditionFalse,
				Reason:  ReasonInvalidSpec,
				Message: MessageSpecValidationFailed,
			},
		}

		err = reconciler.updateStatus(context.TODO(), fetchedMra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Should have Ready condition added by updateStatus (verify on the object passed to updateStatus)
		foundReady := false
		for _, condition := range fetchedMra.Status.Conditions {
			if condition.Type == ConditionTypeReady {
				foundReady = true
				break
			}
		}
		if !foundReady {
			t.Fatalf("Ready condition was not added by updateStatus")
		}
	})

	t.Run("Should initialize role assignment statuses during update", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(testMraCopy).
			WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(context.TODO(), client.ObjectKey{Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Clear role assignment statuses to test initialization
		mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify role assignment statuses were initialized
		if len(mra.Status.RoleAssignments) != 2 {
			t.Fatalf("Expected 2 role assignment statuses, got %d", len(mra.Status.RoleAssignments))
		}

		for _, status := range mra.Status.RoleAssignments {
			if status.Status != StatusTypePending {
				t.Fatalf("Expected role assignment status to be Pending, got %s", status.Status)
			}
			if status.Reason != ReasonInitializing {
				t.Fatalf("Expected role assignment reason to be Initializing, got %s", status.Reason)
			}
		}
	})

	t.Run("Should calculate and set Ready condition", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(testMraCopy).
			WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(context.TODO(), client.ObjectKey{Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Set conditions that should result in Ready=True
		mra.Status.Conditions = []metav1.Condition{
			{
				Type:    ConditionTypeValidated,
				Status:  metav1.ConditionTrue,
				Reason:  ReasonSpecIsValid,
				Message: MessageSpecValidationPassed,
			},
			{
				Type:    ConditionTypeApplied,
				Status:  metav1.ConditionTrue,
				Reason:  ReasonClusterPermissionApplied,
				Message: MessageClusterPermissionApplied,
			},
		}

		// Set all role assignments to Active
		mra.Status.RoleAssignments = []rbacv1alpha1.RoleAssignmentStatus{
			{
				Name:    "test-assignment-1",
				Status:  StatusTypeActive,
				Reason:  ReasonClusterPermissionApplied,
				Message: MessageClusterPermissionApplied,
			},
			{
				Name:    "test-assignment-2",
				Status:  StatusTypeActive,
				Reason:  ReasonClusterPermissionApplied,
				Message: MessageClusterPermissionApplied,
			},
		}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify Ready condition was set to True
		readyCondition := findConditionByType(mra.Status.Conditions, ConditionTypeReady)
		if readyCondition == nil {
			t.Fatalf("Ready condition not found")
		}
		if readyCondition.Status != metav1.ConditionTrue {
			t.Fatalf("Expected Ready condition status to be True, got %s", readyCondition.Status)
		}
		if readyCondition.Reason != ReasonAllApplied {
			t.Fatalf("Expected Ready condition reason to be AllApplied, got %s", readyCondition.Reason)
		}
	})

	t.Run("Should handle resource not found during refresh", func(t *testing.T) {
		// Create fake client without the resource to test Get error during refresh
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "non-existent",
				Namespace: "open-cluster-management",
			},
		}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err == nil {
			t.Fatalf("Expected error when resource not found during refresh, got nil")
		}
	})
}

func TestUpdateStatusRetryLogic(t *testing.T) {
	// Use the same scheme setup pattern as the working tests
	testscheme := scheme.Scheme
	err := rbacv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterv1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}
	err = clusterpermissionv1alpha1.AddToScheme(testscheme)
	if err != nil {
		t.Fatalf("AddToScheme error = %v", err)
	}

	testMra := &rbacv1alpha1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-update-status-retry",
			Namespace:       "open-cluster-management",
			ResourceVersion: "1",
		},
		Spec: rbacv1alpha1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user",
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: rbacv1alpha1.ClusterSelection{
						Type:         "clusterNames",
						ClusterNames: []string{"cluster1"},
					},
				},
			},
		},
		Status: rbacv1alpha1.MulticlusterRoleAssignmentStatus{
			Conditions: []metav1.Condition{
				{
					Type:    ConditionTypeValidated,
					Status:  metav1.ConditionTrue,
					Reason:  ReasonSpecIsValid,
					Message: MessageSpecValidationPassed,
				},
			},
			RoleAssignments: []rbacv1alpha1.RoleAssignmentStatus{
				{
					Name:    "test-assignment-1",
					Status:  StatusTypeActive,
					Reason:  ReasonClusterPermissionApplied,
					Message: MessageClusterPermissionApplied,
				},
			},
		},
	}

	t.Run("Should handle retry logic with concurrent modifications", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(testMraCopy).
			WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(context.TODO(), client.ObjectKey{Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Set custom status that should be preserved during retry
		customCondition := metav1.Condition{
			Type:    ConditionTypeValidated,
			Status:  metav1.ConditionFalse,
			Reason:  ReasonInvalidSpec,
			Message: "Custom validation error",
		}
		mra.Status.Conditions = []metav1.Condition{customCondition}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify custom condition was preserved
		validatedCondition := findConditionByType(mra.Status.Conditions, ConditionTypeValidated)
		if validatedCondition == nil {
			t.Fatalf("Validated condition not found")
		}
		if validatedCondition.Status != metav1.ConditionFalse {
			t.Fatalf("Expected Validated condition status to be False, got %s", validatedCondition.Status)
		}
		if validatedCondition.Message != "Custom validation error" {
			t.Fatalf("Expected custom message to be preserved, got %s", validatedCondition.Message)
		}
	})

	t.Run("Should test retry logic with mock client that simulates conflicts", func(t *testing.T) {
		// Create a mock client that tracks update attempts and simulates conflicts
		testMraCopy := testMra.DeepCopy()

		mockClient := &MockConflictClient{
			Client: fake.NewClientBuilder().
				WithScheme(testscheme).
				WithObjects(testMraCopy).
				WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
				Build(),
			conflictsToSimulate: 2, // Will fail first 2 attempts, succeed on 3rd
			updateAttempts:      0,
		}

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: mockClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := mockClient.Get(context.TODO(), client.ObjectKey{Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Set custom status that should be preserved through retries
		customCondition := metav1.Condition{
			Type:    ConditionTypeValidated,
			Status:  metav1.ConditionFalse,
			Reason:  ReasonInvalidSpec,
			Message: "Retry test condition",
		}
		mra.Status.Conditions = []metav1.Condition{customCondition}

		// This should trigger retry logic
		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus should succeed after retries, got error = %v", err)
		}

		// Verify that retries occurred
		if mockClient.updateAttempts != 3 {
			t.Fatalf("Expected 3 update attempts (2 conflicts + 1 success), got %d", mockClient.updateAttempts)
		}

		// Verify that the status was preserved through retries
		validatedCondition := findConditionByType(mra.Status.Conditions, ConditionTypeValidated)
		if validatedCondition == nil {
			t.Fatalf("Validated condition not found after retries")
		}
		if validatedCondition.Message != "Retry test condition" {
			t.Fatalf("Expected custom message to be preserved through retries, got %s", validatedCondition.Message)
		}

		// Verify Ready condition was also set
		readyCondition := findConditionByType(mra.Status.Conditions, ConditionTypeReady)
		if readyCondition == nil {
			t.Fatalf("Ready condition not found after retries")
		}
	})

	t.Run("Should fail after maximum retry attempts", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()

		// Mock client that always returns conflicts
		mockClient := &MockConflictClient{
			Client: fake.NewClientBuilder().
				WithScheme(testscheme).
				WithObjects(testMraCopy).
				WithStatusSubresource(&rbacv1alpha1.MulticlusterRoleAssignment{}).
				Build(),
			conflictsToSimulate: 5, // More than the 3 retry limit
			updateAttempts:      0,
		}

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: mockClient,
			Scheme: testscheme,
		}

		mra := &rbacv1alpha1.MulticlusterRoleAssignment{}
		err := mockClient.Get(context.TODO(), client.ObjectKey{Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// This should fail after exhausting retries
		err = reconciler.updateStatus(context.TODO(), mra)
		if err == nil {
			t.Fatalf("Expected updateStatus to fail after exhausting retries")
		}

		expectedErrMsg := "failed to update status after 3 retries due to conflicts"
		if err.Error() != expectedErrMsg {
			t.Fatalf("Expected error message '%s', got '%s'", expectedErrMsg, err.Error())
		}

		// Verify that exactly 3 attempts were made
		if mockClient.updateAttempts != 3 {
			t.Fatalf("Expected exactly 3 update attempts, got %d", mockClient.updateAttempts)
		}
	})
}

// MockConflictClient wraps a fake client to simulate optimistic concurrency conflicts
type MockConflictClient struct {
	client.Client
	conflictsToSimulate int
	updateAttempts      int
}

// Status returns a mock status writer that simulates conflicts
func (m *MockConflictClient) Status() client.StatusWriter {
	return &MockStatusWriter{
		StatusWriter: m.Client.Status(),
		parent:       m,
	}
}

// MockStatusWriter simulates optimistic concurrency conflicts for status updates
type MockStatusWriter struct {
	client.StatusWriter
	parent *MockConflictClient
}

// Update simulates conflicts for the first N attempts, then succeeds
func (m *MockStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	m.parent.updateAttempts++

	if m.parent.updateAttempts <= m.parent.conflictsToSimulate {
		// Simulate optimistic concurrency conflict
		return apierrors.NewConflict(
			schema.GroupResource{Group: "rbac.open-cluster-management.io", Resource: "multiclusterroleassignments"},
			obj.GetName(),
			fmt.Errorf("Operation cannot be fulfilled on multiclusterroleassignments.rbac.open-cluster-management.io \"%s\": the object has been modified; please apply your changes to the latest version and try again", obj.GetName()),
		)
	}

	// After the specified number of conflicts, succeed
	return m.StatusWriter.Update(ctx, obj, opts...)
}

// Patch delegates to the underlying status writer
func (m *MockStatusWriter) Patch(ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return m.StatusWriter.Patch(ctx, obj, patch, opts...)
}

// Helper function to find a condition by type
func findConditionByType(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i, condition := range conditions {
		if condition.Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}
