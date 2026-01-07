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
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	mrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1beta1 "open-cluster-management.io/api/cluster/v1beta1"
	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
)

const multiclusterRoleAssignmentNamespace = "open-cluster-management-global-set"

var _ = Describe("MulticlusterRoleAssignment Controller", Ordered, func() {
	ctx := context.Background()
	const multiclusterRoleAssignmentName = "test-multicluster-role-assignment"

	mraNamespacedName := types.NamespacedName{
		Name:      multiclusterRoleAssignmentName,
		Namespace: multiclusterRoleAssignmentNamespace,
	}

	var mra *mrav1beta1.MulticlusterRoleAssignment
	var cp *cpv1alpha1.ClusterPermission

	const roleAssignment1Name = "test-assignment-1"
	const roleAssignment2Name = "test-assignment-2"

	const cluster1Name = "test-cluster-1"
	const cluster2Name = "test-cluster-2"
	const cluster3Name = "test-cluster-3"

	const placement1Name = "test-placement-1"
	const placement2Name = "test-placement-2"

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
	})

	BeforeEach(func() {
		By("Initializing the ClusterPermission")
		cp = &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: cluster2Name,
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{},
		}

		By("Creating shared test Placements and PlacementDecisions")
		Expect(createTestPlacement(ctx, k8sClient, placement1Name)).To(Succeed())
		Expect(createTestPlacementDecision(
			ctx, k8sClient, "decision-1", placement1Name, []string{cluster1Name, cluster2Name})).To(Succeed())

		Expect(createTestPlacement(ctx, k8sClient, placement2Name)).To(Succeed())
		Expect(createTestPlacementDecision(
			ctx, k8sClient, "decision-1", placement2Name, []string{cluster3Name})).To(Succeed())

		By("Creating the MulticlusterRoleAssignment")
		mra = &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:       multiclusterRoleAssignmentName,
				Namespace:  multiclusterRoleAssignmentNamespace,
				Finalizers: []string{finalizerName},
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        roleAssignment1Name,
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
				},
			},
		}
		Expect(k8sClient.Create(ctx, mra)).To(Succeed())
	})

	AfterEach(func() {
		By("Removing finalizer from MulticlusterRoleAssignment")
		mra := &mrav1beta1.MulticlusterRoleAssignment{}
		if err := k8sClient.Get(ctx, mraNamespacedName, mra); err == nil {
			mra.Finalizers = []string{}
			Expect(k8sClient.Update(ctx, mra)).To(Succeed())
		}

		By("Deleting the MulticlusterRoleAssignment")
		mra = &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      mraNamespacedName.Name,
				Namespace: mraNamespacedName.Namespace,
			},
		}
		Expect(k8sClient.Delete(ctx, mra)).To(Succeed())

		By("Waiting for MulticlusterRoleAssignment deletion to complete")
		Eventually(func() bool {
			err := k8sClient.Get(ctx, mraNamespacedName, &mrav1beta1.MulticlusterRoleAssignment{})
			return apierrors.IsNotFound(err)
		}, "10s", "100ms").Should(BeTrue(), "MulticlusterRoleAssignment should be deleted")

		By("Deleting shared test Placements and PlacementDecisions")
		placementNames := []string{placement1Name, placement2Name}
		for _, placementName := range placementNames {
			placement := &clusterv1beta1.Placement{
				ObjectMeta: metav1.ObjectMeta{
					Name:      placementName,
					Namespace: multiclusterRoleAssignmentNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, placement)

			placementDecision := &clusterv1beta1.PlacementDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      placementName + "-decision-1",
					Namespace: multiclusterRoleAssignmentNamespace,
				},
			}
			_ = k8sClient.Delete(ctx, placementDecision)
		}

		By("Deleting all ClusterPermissions")
		clusterNames := []string{cluster1Name, cluster2Name, cluster3Name}
		for _, clusterName := range clusterNames {
			cp := &cpv1alpha1.ClusterPermission{
				ObjectMeta: metav1.ObjectMeta{
					Name:      clusterPermissionManagedName,
					Namespace: clusterName,
				},
			}
			_ = k8sClient.Delete(ctx, cp)
		}
	})

	Context("findMRAsForPlacementDecision", func() {
		// pdReconciler uses manager's client which has field indexes
		// Must be created in BeforeEach because mgr is not available during tree construction
		var pdReconciler *MulticlusterRoleAssignmentReconciler

		BeforeEach(func() {
			pdReconciler = &MulticlusterRoleAssignmentReconciler{
				Client: mgr.GetClient(),
				Scheme: scheme.Scheme,
			}
		})

		It("should return empty when PlacementDecision has no label", func() {
			pd := &clusterv1beta1.PlacementDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pd-no-label",
					Namespace: "default",
				},
			}

			requests := pdReconciler.findMRAsForPlacementDecision(ctx, pd)
			Expect(requests).To(BeEmpty())
		})

		It("should return empty when PlacementDecision has empty label", func() {
			pd := &clusterv1beta1.PlacementDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pd-empty-label",
					Namespace: "default",
					Labels: map[string]string{
						clusterv1beta1.PlacementLabel: "",
					},
				},
			}

			requests := pdReconciler.findMRAsForPlacementDecision(ctx, pd)
			Expect(requests).To(BeEmpty())
		})

		It("should return empty when no MRAs match the placement", func() {
			pd := &clusterv1beta1.PlacementDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "pd-no-match",
					Namespace: multiclusterRoleAssignmentNamespace,
					Labels: map[string]string{
						clusterv1beta1.PlacementLabel: "non-existent-placement",
					},
				},
			}

			requests := pdReconciler.findMRAsForPlacementDecision(ctx, pd)
			Expect(requests).To(BeEmpty())
		})

		It("should return reconcile requests for matching MRAs", func() {
			// Create an MRA that references a test placement
			testMRA := &mrav1beta1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-mra-for-pd-lookup",
					Namespace: multiclusterRoleAssignmentNamespace,
				},
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					Subject: rbacv1.Subject{
						Kind:     "User",
						APIGroup: "rbac.authorization.k8s.io",
						Name:     "test-user-pd-lookup",
					},
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							Name:        "pd-lookup-assignment",
							ClusterRole: "view",
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type: "placements",
								Placements: []mrav1beta1.PlacementRef{
									{
										Name:      "lookup-test-placement",
										Namespace: multiclusterRoleAssignmentNamespace,
									},
								},
							},
						},
					},
				},
			}
			Expect(mgr.GetClient().Create(ctx, testMRA)).To(Succeed())

			// Create PlacementDecision with label pointing to that placement
			pd := &clusterv1beta1.PlacementDecision{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pd-for-lookup",
					Namespace: multiclusterRoleAssignmentNamespace,
					Labels: map[string]string{
						clusterv1beta1.PlacementLabel: "lookup-test-placement",
					},
				},
			}

			// Wait for cache to sync and verify it returns the matching MRA
			var requests []reconcile.Request
			Eventually(func() int {
				requests = pdReconciler.findMRAsForPlacementDecision(ctx, pd)
				return len(requests)
			}).Should(Equal(1), "Expected 1 reconcile request for matching MRA")

			Expect(requests[0].Name).To(Equal(testMRA.Name))
			Expect(requests[0].Namespace).To(Equal(testMRA.Namespace))

			// Cleanup
			Expect(mgr.GetClient().Delete(ctx, testMRA)).To(Succeed())
		})

		It("should return nil when passed wrong object type", func() {
			// Pass a ConfigMap instead of PlacementDecision
			wrongObj := &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "not-a-pd",
					Namespace: "default",
				},
			}

			requests := pdReconciler.findMRAsForPlacementDecision(ctx, wrongObj)
			Expect(requests).To(BeNil())
		})
	})

	Context("extractPlacementKeys", func() {
		It("should extract single placement reference", func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "ns1", Name: "placement1"},
								},
							},
						},
					},
				},
			}
			result := extractPlacementKeys(mra)
			Expect(result).To(ConsistOf("ns1/placement1"))
		})

		It("should extract multiple placement references", func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "ns1", Name: "placement1"},
									{Namespace: "ns2", Name: "placement2"},
								},
							},
						},
					},
				},
			}
			result := extractPlacementKeys(mra)
			Expect(result).To(ConsistOf("ns1/placement1", "ns2/placement2"))
		})

		It("should deduplicate duplicate placements", func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "ns1", Name: "placement1"},
								},
							},
						},
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "ns1", Name: "placement1"}, // duplicate
								},
							},
						},
					},
				},
			}
			result := extractPlacementKeys(mra)
			Expect(result).To(ConsistOf("ns1/placement1"))
		})

		It("should return empty slice when no placements", func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type:       "placements",
								Placements: []mrav1beta1.PlacementRef{},
							},
						},
					},
				},
			}
			result := extractPlacementKeys(mra)
			Expect(result).To(BeEmpty())
		})

		It("should handle mixed placements across role assignments", func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "team-a", Name: "prod"},
								},
							},
						},
						{
							ClusterSelection: mrav1beta1.ClusterSelection{
								Placements: []mrav1beta1.PlacementRef{
									{Namespace: "team-b", Name: "dev"},
								},
							},
						},
					},
				},
			}
			result := extractPlacementKeys(mra)
			Expect(result).To(ConsistOf("team-a/prod", "team-b/dev"))
		})

		It("should return nil for nil input", func() {
			result := extractPlacementKeys(nil)
			Expect(result).To(BeNil())
		})
	})

	Context("PlacementDecision predicate logic", func() {
		It("should return false when decisions unchanged", func() {
			oldPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
						{ClusterName: "cluster-b"},
					},
				},
			}
			newPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
						{ClusterName: "cluster-b"},
					},
				},
			}
			shouldReconcile := !equality.Semantic.DeepEqual(oldPD.Status.Decisions, newPD.Status.Decisions)
			Expect(shouldReconcile).To(BeFalse())
		})

		It("should return true when decisions changed", func() {
			oldPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
					},
				},
			}
			newPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
						{ClusterName: "cluster-b"},
					},
				},
			}
			shouldReconcile := !equality.Semantic.DeepEqual(oldPD.Status.Decisions, newPD.Status.Decisions)
			Expect(shouldReconcile).To(BeTrue())
		})

		It("should return true when cluster removed", func() {
			oldPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
						{ClusterName: "cluster-b"},
					},
				},
			}
			newPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
					},
				},
			}
			shouldReconcile := !equality.Semantic.DeepEqual(oldPD.Status.Decisions, newPD.Status.Decisions)
			Expect(shouldReconcile).To(BeTrue())
		})

		It("should return true when going from empty to non-empty", func() {
			oldPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{},
				},
			}
			newPD := &clusterv1beta1.PlacementDecision{
				Status: clusterv1beta1.PlacementDecisionStatus{
					Decisions: []clusterv1beta1.ClusterDecision{
						{ClusterName: "cluster-a"},
					},
				},
			}
			shouldReconcile := !equality.Semantic.DeepEqual(oldPD.Status.Decisions, newPD.Status.Decisions)
			Expect(shouldReconcile).To(BeTrue())
		})
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

			Expect(mra.Status.RoleAssignments).To(HaveLen(2))
			for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
				Expect(roleAssignmentStatus.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
				Expect(roleAssignmentStatus.Reason).To(Equal(string(mrav1beta1.ReasonSuccessfullyApplied)))
			}
		})

		It("Should prevent duplicate role assignment names via CRD validation", func() {
			By("Attempting to create MulticlusterRoleAssignment with duplicate role assignment names")
			duplicateMRA := &mrav1beta1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-duplicate-mra",
					Namespace: mra.Namespace,
				},
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					Subject: mra.Spec.Subject,
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							Name:        "duplicate-name",
							ClusterRole: "role1",
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type: "placements",
								Placements: []mrav1beta1.PlacementRef{
									{Name: placement1Name, Namespace: mra.Namespace},
								},
							},
						},
						{
							Name:        "duplicate-name",
							ClusterRole: "role2",
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type: "placements",
								Placements: []mrav1beta1.PlacementRef{
									{Name: placement2Name, Namespace: mra.Namespace},
								},
							},
						},
					},
				},
			}

			By("Expecting CRD validation to reject the creation")
			err := k8sClient.Create(ctx, duplicateMRA)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Duplicate value"))
			Expect(err.Error()).To(ContainSubstring("spec.roleAssignments"))
		})

		It("Should complete full reconciliation including ClusterPermission creation", func() {
			By("Reconciling the resource")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, mraNamespacedName, mra)).To(Succeed())

			By("Checking that ClusterPermission was created")
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      clusterPermissionManagedName,
				Namespace: cluster1Name,
			}, cp)
			Expect(err).NotTo(HaveOccurred())
			Expect(cp.Labels[clusterPermissionManagedByLabel]).To(Equal(clusterPermissionManagedByValue))

			By("Checking status conditions")
			appliedFound := false
			readyFound := false

			for _, condition := range mra.Status.Conditions {
				switch condition.Type {
				case string(mrav1beta1.ConditionTypeApplied):
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					appliedFound = true
				case string(mrav1beta1.ConditionTypeReady):
					Expect(condition.Status).To(Equal(metav1.ConditionTrue))
					readyFound = true
				}
			}

			Expect(appliedFound).To(BeTrue(), "Applied condition should be present")
			Expect(readyFound).To(BeTrue(), "Ready condition should be present")

			By("Checking role assignment statuses")
			for _, status := range mra.Status.RoleAssignments {
				if status.Name == mra.Spec.RoleAssignments[0].Name {
					Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
				}
			}
		})

		It("Should cleanup ClusterPermissions when cluster removed from all assignments", func() {
			By("Running first reconcile to create ClusterPermissions in all clusters")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying AppliedClusters contains all three clusters")
			Eventually(func() []string {
				updatedMRA := &mrav1beta1.MulticlusterRoleAssignment{}
				err := k8sClient.Get(ctx, mraNamespacedName, updatedMRA)
				if err != nil {
					return nil
				}
				return updatedMRA.Status.AppliedClusters
			}, "5s", "100ms").Should(ConsistOf(cluster1Name, cluster2Name, cluster3Name))

			By("Verifying ClusterPermissions were created in all clusters")
			for _, clusterName := range []string{cluster1Name, cluster2Name, cluster3Name} {
				cp := &cpv1alpha1.ClusterPermission{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: clusterName,
				}, cp)
				Expect(err).NotTo(HaveOccurred())
			}

			By("Updating PlacementDecision to remove cluster2 (keeping only cluster1)")
			pd := &clusterv1beta1.PlacementDecision{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      placement1Name + "-decision-1",
				Namespace: multiclusterRoleAssignmentNamespace,
			}, pd)
			Expect(err).NotTo(HaveOccurred())

			pd.Status = clusterv1beta1.PlacementDecisionStatus{
				Decisions: []clusterv1beta1.ClusterDecision{
					{ClusterName: cluster1Name},
				},
			}
			err = k8sClient.Status().Update(ctx, pd)
			Expect(err).NotTo(HaveOccurred())

			By("Running second reconcile to trigger cleanup of cluster2")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: mraNamespacedName,
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying AppliedClusters was updated to only contain cluster1 and cluster3")
			Eventually(func() []string {
				updatedMRA := &mrav1beta1.MulticlusterRoleAssignment{}
				err := k8sClient.Get(ctx, mraNamespacedName, updatedMRA)
				if err != nil {
					return nil
				}
				return updatedMRA.Status.AppliedClusters
			}, "5s", "100ms").Should(ConsistOf(cluster1Name, cluster3Name))

			By("Verifying ClusterPermissions still exist in cluster1 and cluster3")
			for _, clusterName := range []string{cluster1Name, cluster3Name} {
				cp := &cpv1alpha1.ClusterPermission{}
				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: clusterName,
				}, cp)
				Expect(err).NotTo(HaveOccurred())
			}

			By("Verifying ClusterPermission was deleted from cluster2")
			Eventually(func() bool {
				cp := &cpv1alpha1.ClusterPermission{}
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				return apierrors.IsNotFound(err)
			}, "5s", "100ms").Should(BeTrue())
		})
	})

	Context("Status Management", func() {
		Describe("setCondition", func() {
			It("Should add new condition when not present", func() {
				reconciler.setCondition(mra, mrav1beta1.ConditionTypeReady, metav1.ConditionTrue,
					mrav1beta1.ReasonAssignmentsReady, "All assignments applied")

				Expect(mra.Status.Conditions).To(HaveLen(1))
				condition := mra.Status.Conditions[0]
				Expect(condition.Type).To(Equal(string(mrav1beta1.ConditionTypeReady)))
				Expect(condition.Status).To(Equal(metav1.ConditionTrue))
				Expect(condition.Reason).To(Equal(string(mrav1beta1.ReasonAssignmentsReady)))
				Expect(condition.Message).To(Equal("All assignments applied"))
				Expect(condition.ObservedGeneration).To(Equal(mra.Generation))
			})

			It("Should update existing condition when status changes", func() {
				reconciler.setCondition(mra, mrav1beta1.ConditionTypeReady, metav1.ConditionTrue,
					mrav1beta1.ReasonAssignmentsReady, "All assignments applied")
				reconciler.setCondition(mra, mrav1beta1.ConditionTypeReady, metav1.ConditionFalse,
					mrav1beta1.ReasonAssignmentsFailure, "Some assignments failed")

				Expect(mra.Status.Conditions).To(HaveLen(1))
				condition := mra.Status.Conditions[0]
				Expect(condition.Type).To(Equal(string(mrav1beta1.ConditionTypeReady)))
				Expect(condition.Status).To(Equal(metav1.ConditionFalse))
				Expect(condition.Reason).To(Equal(string(mrav1beta1.ReasonAssignmentsFailure)))
				Expect(condition.Message).To(Equal("Some assignments failed"))
			})

			It("Should only update ObservedGeneration when condition content is same", func() {
				reconciler.setCondition(mra, mrav1beta1.ConditionTypeReady, metav1.ConditionTrue,
					mrav1beta1.ReasonAssignmentsReady, "All assignments applied")
				originalTime := mra.Status.Conditions[0].LastTransitionTime

				newGeneration := int64(2)
				mra.Generation = newGeneration
				reconciler.setCondition(mra, mrav1beta1.ConditionTypeReady, metav1.ConditionTrue,
					mrav1beta1.ReasonAssignmentsReady, "All assignments applied")

				Expect(mra.Status.Conditions).To(HaveLen(1))
				condition := mra.Status.Conditions[0]
				Expect(condition.LastTransitionTime).To(Equal(originalTime))
				Expect(condition.ObservedGeneration).To(Equal(newGeneration))
			})
		})

		Describe("setRoleAssignmentStatus", func() {
			It("Should add new role assignment status when not present", func() {
				reconciler.setRoleAssignmentStatus(mra, "assignment1", mrav1beta1.StatusTypeActive,
					mrav1beta1.ReasonSuccessfullyApplied, "Successfully applied")

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				status := mra.Status.RoleAssignments[0]
				Expect(status.Name).To(Equal("assignment1"))
				Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
				Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonSuccessfullyApplied)))
				Expect(status.Message).To(Equal("Successfully applied"))
				Expect(status.CreatedAt.Time).NotTo(BeZero())
			})

			It("Should update existing role assignment status", func() {
				var createdTime string
				reconciler.setRoleAssignmentStatus(mra, "assignment1", mrav1beta1.StatusTypePending,
					mrav1beta1.ReasonProcessing, "Initializing")

				status := mra.Status.RoleAssignments[0]

				time.Sleep(100 * time.Microsecond)
				createdTime = status.CreatedAt.String()

				reconciler.setRoleAssignmentStatus(mra, "assignment1", mrav1beta1.StatusTypeActive,
					mrav1beta1.ReasonSuccessfullyApplied, "Successfully applied")

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				status = mra.Status.RoleAssignments[0]
				Expect(status.Name).To(Equal("assignment1"))
				Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
				Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonSuccessfullyApplied)))
				Expect(status.Message).To(Equal("Successfully applied"))
				Expect(status.CreatedAt.String()).To(Equal(createdTime), "CreatedAt should not be updated")
			})
		})

		Describe("initializeRoleAssignmentStatuses", func() {
			It("Should initialize status for all role assignments", func() {
				reconciler.initializeRoleAssignmentStatuses(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					Expect(roleAssignmentStatus.Message).To(Equal("Initializing"))
				}
			})

			It("Should not duplicate or change existing role assignment statuses", func() {
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Message: "Already applied",
					},
				}

				reconciler.initializeRoleAssignmentStatuses(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, status := range mra.Status.RoleAssignments {
					Expect(status).NotTo(BeNil())

					switch status.Name {
					case roleAssignment1Name:
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
						Expect(status.Message).To(Equal("Already applied"))
					case roleAssignment2Name:
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
						Expect(status.Message).To(Equal("Initializing"))
					}
				}
			})
		})

		Describe("clearStaleStatus", func() {
			BeforeEach(func() {
				mra.Generation = 2
				mra.Status.Conditions = []metav1.Condition{
					{
						Type:               string(mrav1beta1.ConditionTypeApplied),
						Status:             metav1.ConditionTrue,
						Reason:             string(mrav1beta1.ReasonSuccessfullyApplied),
						Message:            "Applied successfully",
						ObservedGeneration: 1,
					},
					{
						Type:               string(mrav1beta1.ConditionTypeReady),
						Status:             metav1.ConditionTrue,
						Reason:             string(mrav1beta1.ReasonAssignmentsReady),
						Message:            "role assignments ready",
						ObservedGeneration: 1,
					},
				}
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
						Message: "Applied successfully",
					},
					{
						Name:    roleAssignment2Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
						Message: "Applied successfully",
					},
				}
			})

			It("Should reset Applied condition to False status with re-evaluation message", func() {
				reconciler.clearStaleStatus(mra)

				var appliedCondition *metav1.Condition
				for i, condition := range mra.Status.Conditions {
					if condition.Type == string(mrav1beta1.ConditionTypeApplied) {
						appliedCondition = &mra.Status.Conditions[i]
						break
					}
				}

				Expect(appliedCondition).NotTo(BeNil())
				Expect(appliedCondition.Status).To(Equal(metav1.ConditionFalse))
				Expect(appliedCondition.Reason).To(Equal(string(mrav1beta1.ReasonApplyInProgress)))
				Expect(appliedCondition.Message).To(Equal("Re-evaluating ClusterPermissions"))
				Expect(appliedCondition.ObservedGeneration).To(Equal(mra.Generation))
			})

			It("Should not modify Ready condition", func() {
				originalReadyCondition := mra.Status.Conditions[1]

				reconciler.clearStaleStatus(mra)

				var newReadyCondition *metav1.Condition
				for i, condition := range mra.Status.Conditions {
					if condition.Type == string(mrav1beta1.ConditionTypeReady) {
						newReadyCondition = &mra.Status.Conditions[i]
						break
					}
				}

				Expect(newReadyCondition.Status).To(Equal(originalReadyCondition.Status))
				Expect(newReadyCondition.Reason).To(Equal(originalReadyCondition.Reason))
				Expect(newReadyCondition.Message).To(Equal(originalReadyCondition.Message))
				Expect(newReadyCondition.ObservedGeneration).To(Equal(originalReadyCondition.ObservedGeneration))
			})

			It("Should reset all role assignment statuses to Pending", func() {
				reconciler.clearStaleStatus(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))
				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					Expect(roleAssignmentStatus.Reason).To(Equal(string(mrav1beta1.ReasonProcessing)))
					Expect(roleAssignmentStatus.Message).To(Equal("Re-evaluating"))
				}
			})

			It("Should handle missing Applied condition gracefully", func() {
				mra.Status.Conditions = []metav1.Condition{
					{
						Type:               string(mrav1beta1.ConditionTypeReady),
						Status:             metav1.ConditionTrue,
						Reason:             string(mrav1beta1.ReasonAssignmentsReady),
						Message:            "role assignments ready",
						ObservedGeneration: 1,
					},
				}

				Expect(func() {
					reconciler.clearStaleStatus(mra)
				}).NotTo(Panic())

				Expect(mra.Status.Conditions).To(HaveLen(1))
				Expect(mra.Status.Conditions[0].Type).To(Equal(string(mrav1beta1.ConditionTypeReady)))
			})

			It("Should handle empty role assignments gracefully", func() {
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{}

				Expect(func() {
					reconciler.clearStaleStatus(mra)
				}).NotTo(Panic())

				Expect(mra.Status.RoleAssignments).To(BeEmpty())
			})

			It("Should remove stale role assignment status entries when role assignment names change", func() {
				mra.Spec.RoleAssignments = []mrav1beta1.RoleAssignment{
					{
						Name:        "new-role-assignment-1",
						ClusterRole: "view",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "edit",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
				}
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
						Message: "Applied successfully",
					},
					{
						Name:    roleAssignment2Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
						Message: "Applied successfully",
					},
					{
						Name:    "stale-role-assignment",
						Status:  string(mrav1beta1.StatusTypeError),
						Reason:  string(mrav1beta1.ReasonApplyFailed),
						Message: "Application failed",
					},
				}

				reconciler.clearStaleStatus(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(1))
				Expect(mra.Status.RoleAssignments[0].Name).To(Equal(roleAssignment2Name))
				Expect(mra.Status.RoleAssignments[0].Status).To(Equal(string(mrav1beta1.StatusTypePending)))
				Expect(mra.Status.RoleAssignments[0].Reason).To(Equal(string(mrav1beta1.ReasonProcessing)))
				Expect(mra.Status.RoleAssignments[0].Message).To(Equal("Re-evaluating"))
			})

			It("Should keep all role assignment status entries when names match spec", func() {
				mra.Spec.RoleAssignments = []mrav1beta1.RoleAssignment{
					{
						Name:        roleAssignment1Name,
						ClusterRole: "view",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
					{
						Name:        roleAssignment2Name,
						ClusterRole: "edit",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
				}
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:    roleAssignment1Name,
						Status:  string(mrav1beta1.StatusTypeActive),
						Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
						Message: "Applied successfully",
					},
					{
						Name:    roleAssignment2Name,
						Status:  string(mrav1beta1.StatusTypeError),
						Reason:  string(mrav1beta1.ReasonApplicationFailed),
						Message: "Application failed",
					},
				}

				reconciler.clearStaleStatus(mra)

				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, ra := range mra.Status.RoleAssignments {
					Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					Expect(ra.Reason).To(Equal(string(mrav1beta1.ReasonProcessing)))
					Expect(ra.Message).To(Equal("Re-evaluating"))
				}
			})
		})

		Describe("calculateReadyCondition", func() {
			BeforeEach(func() {
				mra.Status.Conditions = []metav1.Condition{
					{
						Type:   string(mrav1beta1.ConditionTypeApplied),
						Status: metav1.ConditionTrue,
					},
				}

				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:   roleAssignment1Name,
						Status: string(mrav1beta1.StatusTypeActive),
					},
					{
						Name:   roleAssignment2Name,
						Status: string(mrav1beta1.StatusTypeActive),
					},
				}
			})

			It("Should return False when Applied condition is False", func() {
				mra.Status.Conditions[0].Status = metav1.ConditionFalse

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(mrav1beta1.ReasonProvisioningFailed))
				Expect(message).To(Equal("ClusterPermission application failed"))
			})

			It("Should return False when any role assignment failed", func() {
				mra.Status.RoleAssignments[1].Status = string(mrav1beta1.StatusTypeError)

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(mrav1beta1.ReasonAssignmentsFailure))
				Expect(message).To(Equal("1 out of 2 role assignments failed"))
			})

			It("Should return Pending when some role assignments are pending", func() {
				mra.Status.RoleAssignments[1].Status = string(mrav1beta1.StatusTypePending)

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionFalse))
				Expect(reason).To(Equal(mrav1beta1.ReasonAssignmentsPending))
				Expect(message).To(Equal("1 out of 2 role assignments pending"))
			})

			It("Should return True when all role assignments are applied", func() {
				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionTrue))
				Expect(reason).To(Equal(mrav1beta1.ReasonAssignmentsReady))
				Expect(message).To(Equal("2 out of 2 role assignments ready"))
			})

			It("Should return Unknown when status cannot be determined", func() {
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{}

				status, reason, message := reconciler.calculateReadyCondition(mra)
				Expect(status).To(Equal(metav1.ConditionUnknown))
				Expect(reason).To(Equal(mrav1beta1.ReasonAssignmentsPending))
				Expect(message).To(Equal("Status cannot be determined"))
			})
		})

		Describe("updateRoleAssignmentStatuses", func() {
			It("Should accumulate error messages for multi-cluster failures", func() {
				reconciler.initializeRoleAssignmentStatuses(mra)

				state := &ClusterPermissionProcessingState{
					FailedClusters: map[string]error{
						cluster1Name: fmt.Errorf("connection timeout"),
						cluster2Name: fmt.Errorf("permission denied"),
					},
				}

				roleAssignmentClusters := map[string][]string{
					mra.Spec.RoleAssignments[0].Name: {cluster1Name, cluster2Name},
				}

				reconciler.updateRoleAssignmentStatuses(
					mra, []string{cluster1Name, cluster2Name}, state, roleAssignmentClusters)

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonApplicationFailed)))
						Expect(status.Message).To(Equal(fmt.Sprintf(
							"Failed on 2/2 clusters: cluster %s: %s; cluster %s: %s",
							cluster1Name, "connection timeout", cluster2Name, "permission denied")))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Role assignment should have accumulated error messages")
			})

			It("Should preserve existing error status from placement resolution", func() {
				mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
					{
						Name:    mra.Spec.RoleAssignments[0].Name,
						Status:  string(mrav1beta1.StatusTypeError),
						Reason:  string(mrav1beta1.ReasonInvalidReference),
						Message: fmt.Sprintf("%s: placement default/missing-placement not found", "Placement not found"),
					},
				}

				state := &ClusterPermissionProcessingState{
					SuccessClusters: []string{cluster1Name},
				}

				// Empty role assignment clusters map
				roleAssignmentClusters := map[string][]string{}

				reconciler.updateRoleAssignmentStatuses(mra, []string{cluster1Name}, state, roleAssignmentClusters)

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonInvalidReference)))
						Expect(status.Message).To(ContainSubstring("Placement not found"))
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
				clusters, _, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).ToNot(HaveOccurred())
				Expect(clusters).To(HaveLen(3))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name, cluster3Name))
			})

			It("Should update role assignment statuses during aggregation", func() {
				_, _, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).ToNot(HaveOccurred())
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					Expect(roleAssignmentStatus.Reason).To(Equal(string(mrav1beta1.ReasonProcessing)))
					Expect(roleAssignmentStatus.Message).To(SatisfyAll(
						ContainSubstring("Resolved"),
						ContainSubstring("target clusters")),
					)
				}
			})

			It("Should update role assignment status to failed for missing placements", func() {
				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: "missing-placement-1", Namespace: multiclusterRoleAssignmentNamespace},
				}
				mra.Spec.RoleAssignments[1].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: "missing-placement-2", Namespace: multiclusterRoleAssignmentNamespace},
				}

				clusters, _, err := reconciler.aggregateClusters(ctx, mra)
				// NotFound errors don't return error
				Expect(err).ToNot(HaveOccurred())
				Expect(clusters).To(BeEmpty())
				Expect(mra.Status.RoleAssignments).To(HaveLen(2))

				for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
					Expect(roleAssignmentStatus.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
					Expect(roleAssignmentStatus.Reason).To(Equal(string(mrav1beta1.ReasonInvalidReference)))
					Expect(roleAssignmentStatus.Message).To(ContainSubstring("Placement not found"))
					switch roleAssignmentStatus.Name {
					case roleAssignment1Name:
						Expect(roleAssignmentStatus.Message).To(ContainSubstring("missing-placement-1"))
					case roleAssignment2Name:
						Expect(roleAssignmentStatus.Message).To(ContainSubstring("missing-placement-2"))
					}
				}
			})

			It("Should set no clusters resolved and pending status when Placement has no decisions", func() {
				emptyPlacementName := "empty-placement"
				Expect(createTestPlacement(ctx, k8sClient, emptyPlacementName)).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", emptyPlacementName, []string{})).To(Succeed())

				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: emptyPlacementName, Namespace: multiclusterRoleAssignmentNamespace},
				}
				mra.Spec.RoleAssignments[1].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: emptyPlacementName, Namespace: multiclusterRoleAssignmentNamespace},
				}

				clusters, _, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).ToNot(HaveOccurred())
				Expect(clusters).To(BeEmpty())

				for _, status := range mra.Status.RoleAssignments {
					Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonNoMatchingClusters)))
					Expect(status.Message).To(Equal("No clusters match Placement selectors"))
				}
			})

			It("Should handle multiple RoleAssignments with mixed success/failure", func() {
				mra.Spec.RoleAssignments[1].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: "missing-placement", Namespace: multiclusterRoleAssignmentNamespace},
				}

				clusters, _, err := reconciler.aggregateClusters(ctx, mra)
				// NotFound errors don't return error
				Expect(err).ToNot(HaveOccurred())
				Expect(clusters).To(HaveLen(2))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name))

				for _, status := range mra.Status.RoleAssignments {
					switch status.Name {
					case roleAssignment1Name:
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonProcessing)))
					case roleAssignment2Name:
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonInvalidReference)))
					}
				}
			})

			It("Should deduplicate clusters across RoleAssignments", func() {
				overlappingPlacement := "overlapping-placement"
				Expect(createTestPlacement(ctx, k8sClient, overlappingPlacement)).To(Succeed())
				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", overlappingPlacement, []string{cluster2Name, cluster3Name})).To(Succeed())

				mra.Spec.RoleAssignments[1].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: overlappingPlacement, Namespace: multiclusterRoleAssignmentNamespace},
				}

				clusters, _, err := reconciler.aggregateClusters(ctx, mra)
				Expect(err).ToNot(HaveOccurred())
				Expect(clusters).To(HaveLen(3))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name, cluster3Name))
			})
		})

		Describe("resolvePlacementClusters", func() {
			It("Should resolve clusters from a single PlacementDecision", func() {
				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      placement1Name,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(2))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name))
			})

			It("Should resolve clusters from multiple PlacementDecisions", func() {
				multiDecisionPlacement := "multi-decision-placement"
				Expect(createTestPlacement(ctx, k8sClient, multiDecisionPlacement)).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", multiDecisionPlacement, []string{"cluster-a", "cluster-b"})).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-2", multiDecisionPlacement, []string{"cluster-c", "cluster-d"})).To(Succeed())

				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      multiDecisionPlacement,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(4))
				Expect(clusters).To(ContainElements("cluster-a", "cluster-b", "cluster-c", "cluster-d"))
			})

			It("Should return error when Placement not found", func() {
				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      "non-existent-placement",
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("non-existent-placement"))
				Expect(err.Error()).To(ContainSubstring("not found"))
				Expect(clusters).To(BeEmpty())
			})

			It("Should return empty list when no PlacementDecisions exist", func() {
				noDecisionPlacement := "no-decision-placement"
				Expect(createTestPlacement(ctx, k8sClient, noDecisionPlacement)).To(Succeed())

				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      noDecisionPlacement,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(BeEmpty())
			})

			It("Should handle PlacementDecisions with empty Status.Decisions", func() {
				emptyStatusPlacement := "empty-status-placement"
				Expect(createTestPlacement(ctx, k8sClient, emptyStatusPlacement)).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", emptyStatusPlacement, []string{})).To(Succeed())

				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      emptyStatusPlacement,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(BeEmpty())
			})

			It("Should deduplicate clusters within same Placement", func() {
				dupePlacement := "dupe-placement"
				Expect(createTestPlacement(ctx, k8sClient, dupePlacement)).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", dupePlacement, []string{"cluster-x", "cluster-y"})).To(Succeed())

				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-2", dupePlacement, []string{"cluster-y", "cluster-z"})).To(Succeed())

				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      dupePlacement,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(3))
				Expect(clusters).To(ContainElements("cluster-x", "cluster-y", "cluster-z"))
			})

			It("Should return sorted cluster list", func() {
				sortedPlacement := "sorted-placement"
				Expect(createTestPlacement(ctx, k8sClient, sortedPlacement)).To(Succeed())

				Expect(createTestPlacementDecision(ctx, k8sClient, "decision-1", sortedPlacement,
					[]string{
						"zebra-cluster",
						"alpha-cluster",
						"mike-cluster",
						"bravo-cluster",
					})).To(Succeed())

				clusters, err := reconciler.resolvePlacementClusters(ctx, mrav1beta1.PlacementRef{
					Name:      sortedPlacement,
					Namespace: multiclusterRoleAssignmentNamespace,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(4))

				Expect(clusters[0]).To(Equal("alpha-cluster"))
				Expect(clusters[1]).To(Equal("bravo-cluster"))
				Expect(clusters[2]).To(Equal("mike-cluster"))
				Expect(clusters[3]).To(Equal("zebra-cluster"))
			})
		})

		Describe("resolveAllPlacementClusters", func() {
			It("Should resolve clusters from single Placement", func() {
				clusters, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(2))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name))
			})

			It("Should resolve clusters from multiple Placements", func() {
				clusters, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
					{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(HaveLen(3))
				Expect(clusters).To(ContainElements(cluster1Name, cluster2Name, cluster3Name))
			})

			It("Should return error when any Placement not found", func() {
				clusters, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
					{Name: "missing-placement", Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("missing-placement"))
				Expect(clusters).To(BeNil())
			})

			It("Should handle all Placements resolving to empty clusters", func() {
				emptyPlacement1 := "empty-1"
				emptyPlacement2 := "empty-2"
				Expect(createTestPlacement(ctx, k8sClient, emptyPlacement1)).To(Succeed())
				Expect(createTestPlacement(ctx, k8sClient, emptyPlacement2)).To(Succeed())

				clusters, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: emptyPlacement1, Namespace: multiclusterRoleAssignmentNamespace},
					{Name: emptyPlacement2, Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(clusters).To(BeEmpty())
			})

			It("Should maintain deterministic ordering", func() {
				reverseOrderingPlacement := "reverse-order-placement"
				Expect(createTestPlacement(ctx, k8sClient, reverseOrderingPlacement)).To(Succeed())
				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", reverseOrderingPlacement, []string{cluster2Name, cluster1Name})).To(Succeed())

				// Call multiple times to verify consistent ordering
				clusters1, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
					{Name: reverseOrderingPlacement, Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).NotTo(HaveOccurred())

				clusters2, err := reconciler.resolveAllPlacementClusters(ctx, []mrav1beta1.PlacementRef{
					{Name: reverseOrderingPlacement, Namespace: multiclusterRoleAssignmentNamespace},
					{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
				})
				Expect(err).NotTo(HaveOccurred())

				Expect(clusters1).To(Equal(clusters2))
				for i := 1; i < len(clusters1); i++ {
					Expect(clusters1[i-1] < clusters1[i]).To(BeTrue(), "Clusters should be sorted")
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
				Expect(err.Error()).To(ContainSubstring(clusterPermissionManagedName))
				Expect(cp).To(BeNil())
			})

			It("Should return ClusterPermission when it exists and is managed", func() {
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				cp, err := reconciler.getClusterPermission(ctx, cluster2Name)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp).NotTo(BeNil())
				Expect(cp.Name).To(Equal(clusterPermissionManagedName))
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
					clusterPermissionManagedByLabel: "wrong-value",
				}
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeFalse())
			})

			It("Should return true when management label is correct", func() {
				Expect(reconciler.isClusterPermissionManaged(cp)).To(BeTrue())
			})
		})

		Describe("isRoleAssignmentTargetingCluster", func() {
			It("Should return true when cluster is in the list", func() {
				roleAssignment := mrav1beta1.RoleAssignment{
					Name: "test-assignment",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
						},
					},
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment": {cluster1Name, cluster2Name},
				}

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster1Name, roleAssignmentClusters)).To(BeTrue())
				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster2Name, roleAssignmentClusters)).To(BeTrue())
			})

			It("Should return false when cluster is not in the list", func() {
				roleAssignment := mrav1beta1.RoleAssignment{
					Name: "test-assignment",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
						},
					},
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment": {cluster1Name, cluster2Name},
				}

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster3Name, roleAssignmentClusters)).To(BeFalse())
				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, "non-existent", roleAssignmentClusters)).To(BeFalse())
			})

			It("Should return false when role assignment is not in map (placement resolution failed)", func() {
				roleAssignment := mrav1beta1.RoleAssignment{
					Name: "failed-assignment",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "non-existent-placement", Namespace: multiclusterRoleAssignmentNamespace},
						},
					},
				}

				// Empty role assignment clusters map
				roleAssignmentClusters := map[string][]string{}

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster1Name, roleAssignmentClusters)).To(BeFalse())
			})

			It("Should return false when Placement has no clusters", func() {
				emptyPlacement := "empty-targeting-placement"
				Expect(createTestPlacement(ctx, k8sClient, emptyPlacement)).To(Succeed())

				roleAssignment := mrav1beta1.RoleAssignment{
					Name: "empty-assignment",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: emptyPlacement, Namespace: multiclusterRoleAssignmentNamespace},
						},
					},
				}

				roleAssignmentClusters := map[string][]string{
					"empty-assignment": {},
				}

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster1Name, roleAssignmentClusters)).To(BeFalse())
			})

			It("Should handle multiple Placements in ClusterSelection", func() {
				thirdPlacement := "third-placement"
				Expect(createTestPlacement(ctx, k8sClient, thirdPlacement)).To(Succeed())
				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", thirdPlacement, []string{"cluster-alpha", "cluster-beta"})).To(Succeed())

				roleAssignment := mrav1beta1.RoleAssignment{
					Name: "multi-placement-assignment",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							{Name: thirdPlacement, Namespace: multiclusterRoleAssignmentNamespace},
						},
					},
				}

				roleAssignmentClusters := map[string][]string{
					"multi-placement-assignment": {cluster1Name, cluster2Name, "cluster-alpha", "cluster-beta"},
				}

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster1Name, roleAssignmentClusters)).To(BeTrue())
				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster2Name, roleAssignmentClusters)).To(BeTrue())

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, "cluster-alpha", roleAssignmentClusters)).To(BeTrue())
				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, "cluster-beta", roleAssignmentClusters)).To(BeTrue())

				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, cluster3Name, roleAssignmentClusters)).To(BeFalse())
				Expect(reconciler.isRoleAssignmentTargetingCluster(
					roleAssignment, "non-existent", roleAssignmentClusters)).To(BeFalse())
			})
		})

		Describe("ensureClusterPermissionAttempt", func() {
			It("Should create new ClusterPermission with MRA contributions", func() {

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())
				Expect(cp.Labels[clusterPermissionManagedByLabel]).To(Equal(clusterPermissionManagedByValue))

				Expect(cp.Spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.ClusterRoleBindings).To(HaveLen(1))

				binding := (*cp.Spec.ClusterRoleBindings)[0]
				expectedBindingName := reconciler.generateBindingName(mra, "test-assignment-1", "test-role")
				Expect(binding.Name).To(Equal(expectedBindingName))
				Expect(binding.RoleRef.Name).To(Equal("test-role"))
			})

			It("Should update existing ClusterPermission while preserving other MRA contributions", func() {
				cp.Annotations = map[string]string{
					ownerAnnotationPrefix + "other-binding": "other-namespace/other-mra",
				}
				cp.Spec.ClusterRoleBindings = &[]cpv1alpha1.ClusterRoleBinding{
					{
						Name: "other-binding",
						RoleRef: &rbacv1.RoleRef{
							Kind:     clusterRoleKind,
							Name:     "other-role",
							APIGroup: rbacv1.GroupName,
						},
						Subjects: []rbacv1.Subject{{Kind: "User", Name: "other-user"}},
					},
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())

				Expect(cp.Spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.ClusterRoleBindings).To(HaveLen(2))

				Expect(cp.Annotations[ownerAnnotationPrefix+"other-binding"]).To(Equal("other-namespace/other-mra"))
				expectedBindingName := reconciler.generateBindingName(mra, "test-assignment-1", "test-role")
				expectedKey := reconciler.generateOwnerAnnotationKey(expectedBindingName)
				Expect(cp.Annotations[expectedKey]).To(Equal(fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)))
			})

			It("Should handle namespace scoped role assignments (RoleBindings)", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "edit"
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"namespace1", "namespace2"}

				roleAssignmentClusters := map[string][]string{
					"namespaced-role":   {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      clusterPermissionManagedName,
					Namespace: cluster2Name,
				}, cp)
				Expect(err).NotTo(HaveOccurred())

				Expect(cp.Spec.ClusterRoleBindings).To(BeNil())
				Expect(cp.Spec.RoleBindings).NotTo(BeNil())
				Expect(*cp.Spec.RoleBindings).To(HaveLen(2))

				expectedBindingName1 := reconciler.generateBindingName(mra, "namespaced-role", "edit", "namespace1")
				expectedBindingName2 := reconciler.generateBindingName(mra, "namespaced-role", "edit", "namespace2")
				expectedKey1 := reconciler.generateOwnerAnnotationKey(expectedBindingName1)
				expectedKey2 := reconciler.generateOwnerAnnotationKey(expectedBindingName2)
				expectedValue := reconciler.generateMulticlusterRoleAssignmentIdentifier(mra)

				Expect(cp.Annotations[expectedKey1]).To(Equal(expectedValue))
				Expect(cp.Annotations[expectedKey2]).To(Equal(expectedValue))
			})

			It("Should fail when unmanaged ClusterPermission exists", func() {
				unmanagedCP := &cpv1alpha1.ClusterPermission{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterPermissionManagedName,
						Namespace: cluster2Name,
					},
				}
				Expect(k8sClient.Create(ctx, unmanagedCP)).To(Succeed())

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := reconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("not managed by this controller"))
			})

			It("Should handle NotFound gracefully when deleting ClusterPermission (race condition)", func() {
				// Create MRA that doesn't target cluster2 (will trigger delete)
				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
				}

				// Create existing ClusterPermission in cluster2
				cp.Namespace = cluster2Name
				cp.Labels = map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				mockClient := &MockErrorClient{
					Client: k8sClient,
					DeleteError: apierrors.NewNotFound(schema.GroupResource{
						Group:    "rbac.open-cluster-management.io",
						Resource: "clusterpermissions"},
						clusterPermissionManagedName),
					ShouldFailDelete: true,
					TargetResource:   "clusterpermissions",
				}
				mockReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-3"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := mockReconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should handle NotFound gracefully when updating ClusterPermission (race condition)", func() {
				// Create existing ClusterPermission in cluster2
				cp.Namespace = cluster2Name
				cp.Labels = map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				mockClient := &MockErrorClient{
					Client: k8sClient,
					UpdateError: apierrors.NewNotFound(schema.GroupResource{
						Group:    "rbac.open-cluster-management.io",
						Resource: "clusterpermissions"},
						clusterPermissionManagedName),
					ShouldFailUpdate: true,
					TargetResource:   "clusterpermissions",
				}
				mockReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := mockReconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should skip update when ClusterPermission spec and annotations are unchanged", func() {
				// Create existing ClusterPermission with correct spec already
				expectedBindingName := reconciler.generateBindingName(mra, "test-assignment-1", "test-role")
				cp.Namespace = cluster2Name
				cp.Labels = map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				}
				cp.Annotations = map[string]string{
					reconciler.generateOwnerAnnotationKey(expectedBindingName): reconciler.generateMulticlusterRoleAssignmentIdentifier(mra),
				}
				cp.Spec = cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
						{
							Name: expectedBindingName,
							RoleRef: &rbacv1.RoleRef{
								Kind:     clusterRoleKind,
								Name:     "test-role",
								APIGroup: rbacv1.GroupName,
							},
							Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
						},
					},
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				// Track if update was called
				updateCalled := false
				mockClient := &clientWrapper{
					Client: k8sClient,
					updateFn: func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
						updateCalled = true
						return k8sClient.Update(ctx, obj, opts...)
					},
				}
				mockReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := mockReconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())
				Expect(updateCalled).To(BeFalse())
			})

			It("Should update when ClusterPermission spec changes", func() {
				// Create existing ClusterPermission with DIFFERENT spec
				cp.Namespace = cluster2Name
				cp.Labels = map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				}
				cp.Spec = cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
						{
							Name: "different-binding",
							RoleRef: &rbacv1.RoleRef{
								Kind:     clusterRoleKind,
								Name:     "different-role",
								APIGroup: rbacv1.GroupName,
							},
							Subjects: []rbacv1.Subject{{Kind: "User", Name: "different-user"}},
						},
					},
				}
				Expect(k8sClient.Create(ctx, cp)).To(Succeed())

				// Track if update was called
				updateCalled := false
				mockClient := &clientWrapper{
					Client: k8sClient,
					updateFn: func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
						updateCalled = true
						return k8sClient.Update(ctx, obj, opts...)
					},
				}
				mockReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				err := mockReconciler.ensureClusterPermissionAttempt(ctx, mra, cluster2Name, roleAssignmentClusters)
				Expect(err).NotTo(HaveOccurred())
				Expect(updateCalled).To(BeTrue())
			})
		})

		Describe("processClusterPermissions", func() {
			It("Should process ClusterPermissions and set Applied condition", func() {
				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				reconciler.processClusterPermissions(ctx, mra, []string{cluster1Name}, roleAssignmentClusters)

				found := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == string(mrav1beta1.ConditionTypeApplied) {
						Expect(condition.Status).To(Equal(metav1.ConditionTrue))
						Expect(condition.Reason).To(Equal(string(mrav1beta1.ReasonApplied)))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Applied condition should be set to True")
			})

			It("Should mark role assignments as Applied when successful", func() {
				reconciler.initializeRoleAssignmentStatuses(mra)

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				reconciler.processClusterPermissions(ctx, mra, []string{cluster1Name}, roleAssignmentClusters)

				found := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonSuccessfullyApplied)))
						Expect(status.Message).To(SatisfyAll(
							ContainSubstring("Applied to"),
							ContainSubstring("clusters"),
						))
						found = true
						break
					}
				}
				Expect(found).To(BeTrue(), "Role assignment should be marked as Active")
			})

			It("Should handle ClusterPermission creation failures", func() {
				nonExistentCluster := "non-existent-cluster"

				Expect(createTestPlacement(ctx, k8sClient, "test-placement-nonexistent")).To(Succeed())
				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", "test-placement-nonexistent", []string{nonExistentCluster})).To(Succeed())

				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: "test-placement-nonexistent", Namespace: multiclusterRoleAssignmentNamespace},
				}
				reconciler.initializeRoleAssignmentStatuses(mra)

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {nonExistentCluster},
				}

				reconciler.processClusterPermissions(ctx, mra, []string{nonExistentCluster}, roleAssignmentClusters)

				appliedFound := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == string(mrav1beta1.ConditionTypeApplied) {
						Expect(condition.Status).To(Equal(metav1.ConditionFalse))
						Expect(condition.Reason).To(Equal(string(mrav1beta1.ReasonApplyFailed)))
						Expect(condition.Message).To(ContainSubstring("ClusterPermission applications failed"))
						appliedFound = true
						break
					}
				}
				Expect(appliedFound).To(BeTrue(), "Applied condition should be set to False")

				roleAssignmentFound := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonApplicationFailed)))
						Expect(status.Message).To(SatisfyAll(
							ContainSubstring("Failed on"),
							ContainSubstring("clusters"),
						))
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

				Expect(createTestPlacement(
					ctx, k8sClient, "test-placement-mixed")).To(Succeed())
				Expect(createTestPlacementDecision(
					ctx, k8sClient, "decision-1", "test-placement-mixed",
					[]string{existingCluster, nonExistentCluster})).To(Succeed())

				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: "test-placement-mixed", Namespace: multiclusterRoleAssignmentNamespace},
				}
				reconciler.initializeRoleAssignmentStatuses(mra)

				roleAssignmentClusters := map[string][]string{
					"test-assignment-1": {existingCluster, nonExistentCluster},
				}

				reconciler.processClusterPermissions(ctx, mra, []string{existingCluster, nonExistentCluster}, roleAssignmentClusters)

				appliedFound := false
				for _, condition := range mra.Status.Conditions {
					if condition.Type == string(mrav1beta1.ConditionTypeApplied) {
						Expect(condition.Status).To(Equal(metav1.ConditionFalse))
						Expect(condition.Reason).To(Equal(string(mrav1beta1.ReasonApplyFailed)))
						Expect(condition.Message).To(Equal("1 out of 2 ClusterPermission applications failed"))
						appliedFound = true
						break
					}
				}
				Expect(appliedFound).To(BeTrue(), "Applied condition should be set to False for partial failure")

				roleAssignmentFound := false
				for _, status := range mra.Status.RoleAssignments {
					if status.Name == mra.Spec.RoleAssignments[0].Name {
						Expect(status.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						Expect(status.Reason).To(Equal(string(mrav1beta1.ReasonApplicationFailed)))
						Expect(status.Message).To(ContainSubstring("Failed on"))
						Expect(status.Message).To(SatisfyAll(
							ContainSubstring("Failed on"),
							ContainSubstring("clusters"),
							ContainSubstring(nonExistentCluster),
						))
						roleAssignmentFound = true
						break
					}
				}
				Expect(roleAssignmentFound).To(BeTrue(), "Role assignment should be marked as Error for mixed scenario")
			})
		})

		Describe("generateBindingName", func() {
			It("Should generate deterministic hash based binding names", func() {
				bindingName1 := reconciler.generateBindingName(mra, "test-role-assignment", "test-role")
				bindingName2 := reconciler.generateBindingName(mra, "test-role-assignment", "test-role")

				Expect(bindingName1).To(Equal(bindingName2))
				Expect(bindingName1).To(HavePrefix("test-role-"))
				Expect(bindingName1).To(HaveLen(26))
			})

			It("Should generate different names for different inputs", func() {
				bindingName1 := reconciler.generateBindingName(mra, "admin-role-assignment", "admin")
				bindingName2 := reconciler.generateBindingName(mra, "viewer-role-assignment", "view")

				Expect(bindingName1).NotTo(Equal(bindingName2))
				Expect(bindingName1).To(HavePrefix("admin-"))
				Expect(bindingName2).To(HavePrefix("view-"))
			})

			It("Should generate different names for different MRAs", func() {
				otherMRA := &mrav1beta1.MulticlusterRoleAssignment{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "other-mra",
						Namespace: "other-namespace",
					},
				}

				bindingName1 := reconciler.generateBindingName(mra, "test-role-assignment", "test-role")
				bindingName2 := reconciler.generateBindingName(otherMRA, "test-role-assignment", "test-role")

				Expect(bindingName1).NotTo(Equal(bindingName2))
			})

			It("Should sanitize role names for Kubernetes annotation key compatibility", func() {
				bindingName := reconciler.generateBindingName(mra, "monitoring-assignment", "system:monitoring")
				Expect(bindingName).To(HavePrefix("system-monitoring-"))
				Expect(bindingName).NotTo(ContainSubstring(":"))

				bindingName2 := reconciler.generateBindingName(mra, "special-assignment", "-MyRole:With/Chars")
				Expect(bindingName2).To(HavePrefix("myrole-with-chars-"))
				Expect(bindingName2).NotTo(ContainSubstring(":"))
				Expect(bindingName2).NotTo(ContainSubstring("/"))
				Expect(bindingName2).NotTo(ContainSubstring("M"))
			})
		})

		Describe("generateOwnerAnnotationKey", func() {
			It("Should generate correct annotation key with prefix", func() {
				bindingName := "mra-abcd1234efgh"
				key := reconciler.generateOwnerAnnotationKey(bindingName)
				expected := ownerAnnotationPrefix + bindingName
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
					ownerAnnotationPrefix + "binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					ownerAnnotationPrefix + "binding2": "other-namespace/other-mra",
					ownerAnnotationPrefix + "binding3": fmt.Sprintf(
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
					"owner/binding1":       "other-namespace/other-mra",
					"unrelated-annotation": "value",
				}

				ownedBindings := reconciler.extractOwnedBindingNames(cp, mra)
				Expect(ownedBindings).To(BeEmpty())
			})
		})

		Describe("calculateDesiredClusterPermissionSlice", func() {
			It("Should calculate cluster scoped (ClusterRoleBinding) permissions when no target namespaces", func() {
				mra.Spec.RoleAssignments[0].Name = "cluster-admin-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "cluster-admin"
				mra.Spec.RoleAssignments[0].TargetNamespaces = nil

				roleAssignmentClusters := map[string][]string{
					"cluster-admin-role": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2":  {"test-cluster-3"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(HaveLen(1))

				binding := slice.ClusterRoleBindings[0]
				expectedBindingName := reconciler.generateBindingName(mra, "cluster-admin-role", "cluster-admin")
				Expect(binding.Name).To(Equal(expectedBindingName))
				Expect(binding.RoleRef.Name).To(Equal("cluster-admin"))
				Expect(binding.Subjects).To(HaveLen(1))
				Expect(binding.Subjects[0].Name).To(Equal("test-user"))
			})

			It("Should calculate namespace scoped permissions (RoleBinding) when target namespaces specified", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role1"
				mra.Spec.RoleAssignments[0].ClusterRole = "admin"
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"namespace1", "namespace2"}

				roleAssignmentClusters := map[string][]string{
					"namespaced-role1":  {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

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
				mra.Spec.RoleAssignments[0].ClusterSelection.Placements = []mrav1beta1.PlacementRef{
					{Name: placement2Name, Namespace: multiclusterRoleAssignmentNamespace},
				}

				roleAssignmentClusters := map[string][]string{
					"other-cluster-role": {"test-cluster-3"},
					"test-assignment-2":  {"test-cluster-3"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

				Expect(slice.ClusterRoleBindings).To(BeEmpty())
				Expect(slice.RoleBindings).To(BeEmpty())
				Expect(slice.OwnerAnnotations).To(BeEmpty())
			})

			It("Should generate correct owner annotations for cluster-scoped permissions", func() {
				mra.Spec.RoleAssignments[0].Name = "cluster-admin-role"
				mra.Spec.RoleAssignments[0].ClusterRole = "cluster-admin"
				mra.Spec.RoleAssignments[0].TargetNamespaces = nil

				roleAssignmentClusters := map[string][]string{
					"cluster-admin-role": {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2":  {"test-cluster-3"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

				Expect(slice.OwnerAnnotations).To(HaveLen(1))

				expectedBindingName := reconciler.generateBindingName(mra, "cluster-admin-role", "cluster-admin")
				expectedAnnotationKey := ownerAnnotationPrefix + expectedBindingName
				expectedMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedAnnotationKey, expectedMRAIdentifier))
			})

			It("Should generate correct owner annotations for namespace scoped permissions", func() {
				mra.Spec.RoleAssignments[0].Name = "namespaced-role2"
				mra.Spec.RoleAssignments[0].ClusterRole = "edit"
				mra.Spec.RoleAssignments[0].TargetNamespaces = []string{"ns1", "ns2"}

				roleAssignmentClusters := map[string][]string{
					"namespaced-role2":  {"test-cluster-1", "test-cluster-2"},
					"test-assignment-2": {"test-cluster-3"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

				Expect(slice.OwnerAnnotations).To(HaveLen(2))

				bindingName1 := reconciler.generateBindingName(mra, "namespaced-role2", "edit", "ns1")
				bindingName2 := reconciler.generateBindingName(mra, "namespaced-role2", "edit", "ns2")
				expectedMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				expectedKey1 := ownerAnnotationPrefix + bindingName1
				expectedKey2 := ownerAnnotationPrefix + bindingName2

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedKey1, expectedMRAIdentifier))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedKey2, expectedMRAIdentifier))
			})

			It("Should generate annotations for multiple role assignments targeting same cluster", func() {
				mra.Spec.RoleAssignments = []mrav1beta1.RoleAssignment{
					{
						Name:        "admin-role",
						ClusterRole: "cluster-admin",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
					{
						Name:        "edit-role",
						ClusterRole: "edit",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
						TargetNamespaces: []string{"development"},
					},
				}

				roleAssignmentClusters := map[string][]string{
					"admin-role": {"test-cluster-1", "test-cluster-2"},
					"edit-role":  {"test-cluster-1", "test-cluster-2"},
				}

				slice := reconciler.calculateDesiredClusterPermissionSlice(mra, cluster1Name, roleAssignmentClusters)

				Expect(slice.ClusterRoleBindings).To(HaveLen(1))
				Expect(slice.RoleBindings).To(HaveLen(1))
				Expect(slice.OwnerAnnotations).To(HaveLen(2))

				expectedMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)

				adminBindingName := reconciler.generateBindingName(mra, "admin-role", "cluster-admin")
				editBindingName := reconciler.generateBindingName(mra, "edit-role", "edit", "development")

				expectedAdminKey := ownerAnnotationPrefix + adminBindingName
				expectedEditKey := ownerAnnotationPrefix + editBindingName

				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedAdminKey, expectedMRAIdentifier))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(expectedEditKey, expectedMRAIdentifier))
			})
		})

		Describe("extractOthersClusterPermissionSlice", func() {
			It("Should extract bindings not owned by current MRA", func() {
				cp.Annotations = map[string]string{
					ownerAnnotationPrefix + "cluster-role-binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					ownerAnnotationPrefix + "cluster-role-binding2": "other-namespace/other-mra",
					ownerAnnotationPrefix + "role-binding1": fmt.Sprintf(
						"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName),
					ownerAnnotationPrefix + "role-binding2": "other-namespace/other-mra",
					"unrelated-annotation":                  "value",
				}
				cp.Spec.ClusterRoleBindings = &[]cpv1alpha1.ClusterRoleBinding{
					{Name: "cluster-role-binding1"}, // Owned by current MRA
					{Name: "cluster-role-binding2"}, // Owned by other MRA
					{Name: "cluster-role-binding4"}, // Not in annotations (orphan, should get removed)
				}
				cp.Spec.RoleBindings = &[]cpv1alpha1.RoleBinding{
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
					ownerAnnotationPrefix + "tracked-binding": "other-namespace/other-mra",
					"unrelated-annotation":                    "value",
				}
				cp.Spec.ClusterRoleBindings = &[]cpv1alpha1.ClusterRoleBinding{
					{Name: "tracked-binding"},   // Has ownership annotation
					{Name: "orphaned-binding1"}, // No ownership annotation
					{Name: "orphaned-binding2"}, // No ownership annotation
				}
				cp.Spec.RoleBindings = &[]cpv1alpha1.RoleBinding{
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
					ownerAnnotationPrefix + "current-binding1": currentMRAIdentifier,
					ownerAnnotationPrefix + "current-binding2": currentMRAIdentifier,
					ownerAnnotationPrefix + "other-binding1":   "other-namespace/other-mra1",
					ownerAnnotationPrefix + "other-binding2":   "other-namespace/other-mra2",
					ownerAnnotationPrefix + "other-binding3":   "other-namespace/other-mra3",
					"unrelated-annotation":                     "should-be-preserved",
					"another-unrelated":                        "also-preserved",
				}
				cp.Spec.ClusterRoleBindings = &[]cpv1alpha1.ClusterRoleBinding{
					{Name: "current-binding1"},
					{Name: "other-binding1"},
					{Name: "other-binding2"},
				}
				cp.Spec.RoleBindings = &[]cpv1alpha1.RoleBinding{
					{Name: "current-binding2", Namespace: "ns1"},
					{Name: "other-binding3", Namespace: "ns2"},
				}

				slice := reconciler.extractOthersClusterPermissionSlice(cp, mra)

				Expect(slice.OwnerAnnotations).To(HaveLen(5))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					ownerAnnotationPrefix+"other-binding1", "other-namespace/other-mra1"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					ownerAnnotationPrefix+"other-binding2", "other-namespace/other-mra2"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					ownerAnnotationPrefix+"other-binding3", "other-namespace/other-mra3"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("unrelated-annotation", "should-be-preserved"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("another-unrelated", "also-preserved"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "current-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "current-binding2"))
			})

			It("Should exclude orphaned annotations that have no corresponding bindings", func() {
				currentMRAIdentifier := fmt.Sprintf(
					"%s/%s", multiclusterRoleAssignmentNamespace, multiclusterRoleAssignmentName)
				cp.Annotations = map[string]string{
					ownerAnnotationPrefix + "current-binding1": currentMRAIdentifier,
					ownerAnnotationPrefix + "current-binding2": currentMRAIdentifier,
					ownerAnnotationPrefix + "other-binding1":   "other-namespace/other-mra",
					ownerAnnotationPrefix + "other-binding2":   "other-namespace/other-mra",
					ownerAnnotationPrefix + "missing-binding1": "other-namespace/other-mra",
					ownerAnnotationPrefix + "missing-binding2": "other-namespace/other-mra3",
					"non-owner-annotation":                     "preserved",
				}
				cp.Spec.ClusterRoleBindings = &[]cpv1alpha1.ClusterRoleBinding{
					{Name: "current-binding1"},
					{Name: "other-binding1"},
				}
				cp.Spec.RoleBindings = &[]cpv1alpha1.RoleBinding{
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
					ownerAnnotationPrefix+"other-binding1", "other-namespace/other-mra"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue(
					ownerAnnotationPrefix+"other-binding2", "other-namespace/other-mra"))
				Expect(slice.OwnerAnnotations).To(HaveKeyWithValue("non-owner-annotation", "preserved"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "missing-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "missing-binding2"))

				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "current-binding1"))
				Expect(slice.OwnerAnnotations).NotTo(HaveKey(ownerAnnotationPrefix + "current-binding2"))
			})
		})

		Describe("mergeClusterPermissionSpecs", func() {
			It("Should merge ClusterRoleBindings from both slices", func() {
				others := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "other-binding1"},
						{Name: "other-binding2"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
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
					RoleBindings: []cpv1alpha1.RoleBinding{
						{Name: "other-role-binding1"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					RoleBindings: []cpv1alpha1.RoleBinding{
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
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "other-cluster-binding1"},
						{Name: "other-cluster-binding2"},
					},
					RoleBindings: []cpv1alpha1.RoleBinding{
						{Name: "other-role-binding1", Namespace: "ns1"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "desired-cluster-binding1"},
					},
					RoleBindings: []cpv1alpha1.RoleBinding{
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

			It("Should sort bindings by name for deterministic ordering", func() {
				others := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "z-binding"},
						{Name: "a-binding"},
					},
				}
				desired := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "m-binding"},
					},
				}

				spec := reconciler.mergeClusterPermissionSpecs(others, desired)

				Expect(spec.ClusterRoleBindings).NotTo(BeNil())
				Expect(*spec.ClusterRoleBindings).To(HaveLen(3))

				bindings := *spec.ClusterRoleBindings
				Expect(bindings[0].Name).To(Equal("a-binding"))
				Expect(bindings[1].Name).To(Equal("m-binding"))
				Expect(bindings[2].Name).To(Equal("z-binding"))
			})

			It("Should produce consistent results regardless of merge order", func() {
				slice1 := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "binding-a"},
					},
				}
				slice2 := ClusterPermissionBindingSlice{
					ClusterRoleBindings: []cpv1alpha1.ClusterRoleBinding{
						{Name: "binding-b"},
					},
				}

				spec1 := reconciler.mergeClusterPermissionSpecs(slice1, slice2)
				spec2 := reconciler.mergeClusterPermissionSpecs(slice2, slice1)

				Expect(spec1.ClusterRoleBindings).NotTo(BeNil())
				Expect(spec2.ClusterRoleBindings).NotTo(BeNil())
				Expect((*spec1.ClusterRoleBindings)[0].Name).To(Equal("binding-a"))
				Expect((*spec1.ClusterRoleBindings)[1].Name).To(Equal("binding-b"))
				Expect((*spec2.ClusterRoleBindings)[0].Name).To(Equal("binding-a"))
				Expect((*spec2.ClusterRoleBindings)[1].Name).To(Equal("binding-b"))
			})
		})

		Describe("mergeClusterPermissionAnnotations", func() {
			It("Should merge annotations from both slices", func() {
				others := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						ownerAnnotationPrefix + "binding1": "other/mra1",
						ownerAnnotationPrefix + "binding2": "other/mra2",
						"unrelated-annotation":             "value",
					},
				}
				desired := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						ownerAnnotationPrefix + "binding3": "current/mra",
						ownerAnnotationPrefix + "binding4": "current/mra",
					},
				}

				annotations := reconciler.mergeClusterPermissionAnnotations(others, desired)

				Expect(annotations).To(HaveLen(5))
				Expect(annotations[ownerAnnotationPrefix+"binding1"]).To(Equal("other/mra1"))
				Expect(annotations[ownerAnnotationPrefix+"binding2"]).To(Equal("other/mra2"))
				Expect(annotations[ownerAnnotationPrefix+"binding3"]).To(Equal("current/mra"))
				Expect(annotations[ownerAnnotationPrefix+"binding4"]).To(Equal("current/mra"))
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
						ownerAnnotationPrefix + "binding1": "other/mra",
					},
				}
				desired := ClusterPermissionBindingSlice{
					OwnerAnnotations: map[string]string{
						ownerAnnotationPrefix + "binding1": "current/mra",
					},
				}

				annotations := reconciler.mergeClusterPermissionAnnotations(others, desired)

				Expect(annotations).To(HaveLen(1))
				Expect(annotations[ownerAnnotationPrefix+"binding1"]).To(Equal("current/mra"))
			})
		})

		Describe("isClusterPermissionSpecEmpty", func() {
			It("Should return true when both are nil", func() {
				spec := cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: nil,
					RoleBindings:        nil,
				}
				Expect(reconciler.isClusterPermissionSpecEmpty(spec)).To(BeTrue())
			})

			It("Should return true when both are empty slices", func() {
				emptyClusterRoleBindings := []cpv1alpha1.ClusterRoleBinding{}
				emptyRoleBindings := []cpv1alpha1.RoleBinding{}
				spec := cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: &emptyClusterRoleBindings,
					RoleBindings:        &emptyRoleBindings,
				}
				Expect(reconciler.isClusterPermissionSpecEmpty(spec)).To(BeTrue())
			})

			It("Should return false when ClusterRoleBindings has items", func() {
				clusterRoleBindings := []cpv1alpha1.ClusterRoleBinding{
					{
						Name: "test-binding",
						RoleRef: &rbacv1.RoleRef{
							Kind:     clusterRoleKind,
							Name:     "test-role",
							APIGroup: rbacv1.GroupName,
						},
					},
				}
				spec := cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: &clusterRoleBindings,
					RoleBindings:        nil,
				}
				Expect(reconciler.isClusterPermissionSpecEmpty(spec)).To(BeFalse())
			})

			It("Should return false when RoleBindings has items", func() {
				roleBindings := []cpv1alpha1.RoleBinding{
					{
						Name:      "test-role-binding",
						Namespace: "test-namespace",
					},
				}
				spec := cpv1alpha1.ClusterPermissionSpec{
					ClusterRoleBindings: nil,
					RoleBindings:        &roleBindings,
				}
				Expect(reconciler.isClusterPermissionSpecEmpty(spec)).To(BeFalse())
			})
		})
	})

	Context("Reconcile Error Handling", func() {
		const errorTestMRAName = "error-test-mra"
		const errorTestNamespaceName = "error-test-namespace"

		var errorTestMRA *mrav1beta1.MulticlusterRoleAssignment
		var errorTestNamespace *corev1.Namespace

		BeforeEach(func() {
			errorTestNamespace = &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: errorTestNamespaceName}}
			if err := k8sClient.Get(
				ctx, client.ObjectKey{Name: errorTestNamespace.Name}, errorTestNamespace); err != nil {

				Expect(k8sClient.Create(ctx, errorTestNamespace)).To(Succeed())
			}

			errorTestMRA = &mrav1beta1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{
					Name:       errorTestMRAName,
					Namespace:  errorTestNamespaceName,
					Finalizers: []string{finalizerName},
				},
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					Subject: rbacv1.Subject{Kind: "User", Name: "test-user"},
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							Name:        "error-test-assignment",
							ClusterRole: "error-test-role",
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type: "placements",
								Placements: []mrav1beta1.PlacementRef{
									{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
								},
							},
						},
					},
				},
			}
		})

		AfterEach(func() {
			mra := &mrav1beta1.MulticlusterRoleAssignment{}
			if err := k8sClient.Get(ctx, client.ObjectKey{
				Name:      errorTestMRAName,
				Namespace: errorTestNamespaceName,
			}, mra); err == nil {
				mra.Finalizers = []string{}
				_ = k8sClient.Update(ctx, mra)
				_ = k8sClient.Delete(ctx, mra)
			}
		})

		Context("Get Operation Errors", func() {
			It("Should handle resource not found gracefully", func() {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "non-existent-mra",
						Namespace: errorTestNamespaceName,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should return error when Get fails with non-NotFound error", func() {
				mockClient := &MockErrorClient{
					Client:     k8sClient,
					GetError:   fmt.Errorf("get operation failed"),
					ShouldFail: true,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      "any-name",
						Namespace: errorTestNamespaceName,
					},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("get operation failed"))
			})
		})

		Context("Finalizer Conflicts", func() {
			It("Should handle finalizer add conflict and requeue", func() {
				errorTestMRA.Finalizers = nil
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockConflictClient{
					Client:              k8sClient,
					conflictsToSimulate: 1,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				result, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(standardRequeueDelay))
			})

			It("Should handle finalizer remove conflict and requeue", func() {
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())
				Expect(k8sClient.Delete(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockConflictClient{
					Client:              k8sClient,
					conflictsToSimulate: 1,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				result, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(standardRequeueDelay))
			})

			It("Should return error when finalizer update fails with non-conflict error", func() {
				errorTestMRA.Finalizers = nil
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockErrorClient{
					Client:      k8sClient,
					UpdateError: fmt.Errorf("finalizer update failed"),
					ShouldFail:  true,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("finalizer update failed"))
			})
		})

		Context("Early Return Logic", func() {
			It("Should skip reconcile when all conditions are current for generation", func() {
				errorTestMRA.Generation = 1
				errorTestMRA.Status.Conditions = []metav1.Condition{
					{Type: string(mrav1beta1.ConditionTypeApplied), Status: metav1.ConditionTrue, ObservedGeneration: 1},
					{Type: string(mrav1beta1.ConditionTypeReady), Status: metav1.ConditionTrue, ObservedGeneration: 1},
				}
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				result, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result).To(Equal(reconcile.Result{}))
			})
		})

		Context("Status Update Failures", func() {
			It("Should return error when status update fails during reconciliation", func() {
				errorTestMRA.Spec.RoleAssignments = []mrav1beta1.RoleAssignment{
					{
						Name:        "assignment-1",
						ClusterRole: "role1",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				// Create a mock client that fails on status updates
				mockClient := &MockErrorClient{
					Client:            k8sClient,
					StatusUpdateError: fmt.Errorf("status update failed"),
					ShouldFailStatus:  true,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("status update failed"))
			})

			It("Should handle status update conflict and requeue", func() {
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockConflictClient{
					Client:              k8sClient,
					conflictsToSimulate: 1,
					statusConflict:      true,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				result, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(standardRequeueDelay))
			})
		})

		Context("Cluster Operations Errors", func() {
			It("Should handle aggregateClusters (Placement not found) failure with status update attempt", func() {
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockErrorClient{
					Client: k8sClient,
					GetError: apierrors.NewNotFound(schema.GroupResource{
						Group: "cluster.open-cluster-management.io", Resource: "placements"}, "test-placement-1"),
					ShouldFailGet:  true,
					TargetResource: "placements",
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				// NotFound errors do not return error
				Expect(err).NotTo(HaveOccurred())

				err = k8sClient.Get(ctx, types.NamespacedName{
					Name:      errorTestMRA.Name,
					Namespace: errorTestMRA.Namespace,
				}, errorTestMRA)
				Expect(err).NotTo(HaveOccurred())

				Expect(errorTestMRA.Status.RoleAssignments).To(HaveLen(1))
				Expect(errorTestMRA.Status.RoleAssignments[0].Status).To(Equal(string(mrav1beta1.StatusTypeError)))
				Expect(errorTestMRA.Status.RoleAssignments[0].Reason).To(Equal(string(mrav1beta1.ReasonInvalidReference)))
				Expect(errorTestMRA.Status.RoleAssignments[0].Message).To(ContainSubstring("Placement not found"))
			})

			It("Should handle status.appliedClusters for previous clusters", func() {
				errorTestMRA.Status.AppliedClusters = []string{"cluster-a", "cluster-b", "cluster-c"}
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("Should requeue after cluster permission failures", func() {
				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockErrorClient{
					Client:           k8sClient,
					CreateError:      fmt.Errorf("cluster permission creation failed"),
					ShouldFailCreate: true,
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				result, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(result.RequeueAfter).To(Equal(clusterPermissionFailureRequeueDelay))
			})

			It("Should handle deletion cleanup failure", func() {
				existingCP := &cpv1alpha1.ClusterPermission{
					ObjectMeta: metav1.ObjectMeta{
						Name:      clusterPermissionManagedName,
						Namespace: cluster1Name,
						Labels: map[string]string{
							clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
						},
						Annotations: map[string]string{
							ownerAnnotationPrefix + "other-binding":          "some-namespace/some-other-mra",
							ownerAnnotationPrefix + "error-test-mra-binding": "error-test-namespace/error-test-mra",
						},
					},
					Spec: cpv1alpha1.ClusterPermissionSpec{
						ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
							{
								Name: "other-binding",
								RoleRef: &rbacv1.RoleRef{
									Kind:     clusterRoleKind,
									Name:     "other-role",
									APIGroup: rbacv1.GroupName,
								},
								Subjects: []rbacv1.Subject{{Kind: "User", Name: "other-user"}},
							},
							{
								Name: "error-test-mra-binding",
								RoleRef: &rbacv1.RoleRef{
									Kind:     clusterRoleKind,
									Name:     "error-test-role",
									APIGroup: rbacv1.GroupName,
								},
								Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user"}},
							},
						},
					},
				}
				Expect(k8sClient.Create(ctx, existingCP)).To(Succeed())

				Expect(k8sClient.Create(ctx, errorTestMRA)).To(Succeed())
				Expect(k8sClient.Delete(ctx, errorTestMRA)).To(Succeed())

				mockClient := &MockErrorClient{
					Client:           k8sClient,
					UpdateError:      fmt.Errorf("failed to update ClusterPermission during deletion cleanup"),
					ShouldFailUpdate: true,
					TargetResource:   "clusterpermissions",
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      errorTestMRA.Name,
						Namespace: errorTestMRA.Namespace,
					},
				})
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("failed to update ClusterPermission during deletion cleanup"))
			})
		})
	})

	Context("Finalizer handling in Reconcile", func() {
		var mra *mrav1beta1.MulticlusterRoleAssignment
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

			mra = &mrav1beta1.MulticlusterRoleAssignment{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-finalizer-mra",
					Namespace: "test-namespace",
				},
				Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
					Subject: rbacv1.Subject{
						Kind: "User",
						Name: "test-user",
					},
					RoleAssignments: []mrav1beta1.RoleAssignment{
						{
							Name:        "test-assignment",
							ClusterRole: "test-role",
							ClusterSelection: mrav1beta1.ClusterSelection{
								Type: "placements",
								Placements: []mrav1beta1.PlacementRef{
									{Name: placement1Name, Namespace: multiclusterRoleAssignmentNamespace},
								},
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
				updatedMra := &mrav1beta1.MulticlusterRoleAssignment{}
				err = k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, updatedMra)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedMra.Finalizers).To(ContainElement(finalizerName))
			})

			It("Should not add finalizer if already present", func() {
				// Create MRA with finalizer already present
				mra.Finalizers = []string{finalizerName}
				Expect(k8sClient.Create(ctx, mra)).To(Succeed())

				// Get initial resource version
				initialMra := &mrav1beta1.MulticlusterRoleAssignment{}
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
				updatedMra := &mrav1beta1.MulticlusterRoleAssignment{}
				err = k8sClient.Get(ctx, client.ObjectKey{
					Name:      mra.Name,
					Namespace: mra.Namespace,
				}, updatedMra)
				Expect(err).NotTo(HaveOccurred())
				Expect(updatedMra.Finalizers).To(ContainElement(finalizerName))
			})
		})

		Describe("Removing finalizer during deletion", func() {
			BeforeEach(func() {
				// Create MRA with finalizer
				mra.Finalizers = []string{finalizerName}
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
					}, &mrav1beta1.MulticlusterRoleAssignment{})
					return apierrors.IsNotFound(err)
				}, "5s", "100ms").Should(BeTrue(), "Resource should be deleted after finalizer removal")
			})

			It("Should handle MRA already deleted (not found) when removing finalizer (race condition)", func() {
				Expect(k8sClient.Delete(ctx, mra)).To(Succeed())

				mockClient := &MockErrorClient{
					Client: k8sClient,
					UpdateError: apierrors.NewNotFound(schema.GroupResource{
						Group:    "rbac.open-cluster-management.io",
						Resource: "multiclusterroleassignments"},
						mra.Name),
					ShouldFailUpdate: true,
					TargetResource:   "multiclusterroleassignments",
				}
				errorReconciler := &MulticlusterRoleAssignmentReconciler{
					Client: mockClient,
					Scheme: k8sClient.Scheme(),
				}

				_, err := errorReconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: client.ObjectKey{
						Name:      mra.Name,
						Namespace: mra.Namespace,
					},
				})
				Expect(err).NotTo(HaveOccurred())
			})
		})

		AfterEach(func() {
			testMra := &mrav1beta1.MulticlusterRoleAssignment{}
			err := k8sClient.Get(ctx, client.ObjectKey{
				Name:      mra.Name,
				Namespace: mra.Namespace,
			}, testMra)

			if apierrors.IsNotFound(err) {
				return
			}
			Expect(err).NotTo(HaveOccurred())

			testMra.Finalizers = []string{}
			err = k8sClient.Update(ctx, testMra)
			Expect(err).NotTo(HaveOccurred())

			err = k8sClient.Delete(ctx, testMra)
			if !apierrors.IsNotFound(err) {
				Expect(err).NotTo(HaveOccurred())
			}
		})
	})
})

func TestHandleMulticlusterRoleAssignmentDeletion(t *testing.T) {
	var testscheme = scheme.Scheme
	for _, addToScheme := range []func(*runtime.Scheme) error{
		mrav1beta1.AddToScheme,
		clusterv1beta1.AddToScheme,
		cpv1alpha1.AddToScheme,
		corev1.AddToScheme,
	} {
		if err := addToScheme(testscheme); err != nil {
			t.Fatalf("AddToScheme error = %v", err)
		}
	}

	testMra1 := &mrav1beta1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample1",
			Namespace: "open-cluster-management",
		},
		Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user1",
			},
			RoleAssignments: []mrav1beta1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement1", Namespace: "open-cluster-management"},
						},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement2", Namespace: "open-cluster-management"},
						},
					},
				},
			},
		},
	}

	testMra2 := &mrav1beta1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample2",
			Namespace: "open-cluster-management",
		},
		Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user2",
			},
			RoleAssignments: []mrav1beta1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement1", Namespace: "open-cluster-management"},
						},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement2", Namespace: "open-cluster-management"},
						},
					},
				},
			},
		},
	}

	reconciler := &MulticlusterRoleAssignmentReconciler{}

	bindingNameMra1Assignment1 := reconciler.generateBindingName(testMra1, "test-assignment-1", "test-role")
	bindingNameMra1Assignment2 := reconciler.generateBindingName(testMra1, "test-assignment-2", "test-role")
	bindingNameMra2Assignment1 := reconciler.generateBindingName(testMra2, "test-assignment-1", "test-role")
	bindingNameMra2Assignment2 := reconciler.generateBindingName(testMra2, "test-assignment-2", "test-role")

	testCp1 := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mra-managed-permissions",
			Namespace: "cluster1",
			Annotations: map[string]string{
				ownerAnnotationPrefix +
					bindingNameMra2Assignment1: "open-cluster-management/multiclusterroleassignment-sample2",
				ownerAnnotationPrefix +
					bindingNameMra1Assignment1: "open-cluster-management/multiclusterroleassignment-sample1",
			},
			Labels: map[string]string{
				clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
			},
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{
			ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
				{
					Name: bindingNameMra1Assignment1,
					RoleRef: &rbacv1.RoleRef{
						Kind:     clusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user1"}},
				},
				{
					Name: bindingNameMra2Assignment1,
					RoleRef: &rbacv1.RoleRef{
						Kind:     clusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user2"}},
				},
			},
		},
	}

	testCp2 := &cpv1alpha1.ClusterPermission{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mra-managed-permissions",
			Namespace: "cluster2",
			Annotations: map[string]string{
				ownerAnnotationPrefix +
					bindingNameMra2Assignment2: "open-cluster-management/multiclusterroleassignment-sample2",
				ownerAnnotationPrefix +
					bindingNameMra1Assignment2: "open-cluster-management/multiclusterroleassignment-sample1",
			},
			Labels: map[string]string{
				clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
			},
		},
		Spec: cpv1alpha1.ClusterPermissionSpec{
			ClusterRoleBindings: &[]cpv1alpha1.ClusterRoleBinding{
				{
					Name: bindingNameMra1Assignment2,
					RoleRef: &rbacv1.RoleRef{
						Kind:     clusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user1"}},
				},
				{
					Name: bindingNameMra2Assignment2,
					RoleRef: &rbacv1.RoleRef{
						Kind:     clusterRoleKind,
						Name:     "test-role",
						APIGroup: rbacv1.GroupName,
					},
					Subjects: []rbacv1.Subject{{Kind: "User", Name: "test-user2"}},
				},
			},
		},
	}

	placement1 := &clusterv1beta1.Placement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement1",
			Namespace: "open-cluster-management",
		},
	}

	placementDecision1 := &clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement1-decision-1",
			Namespace: "open-cluster-management",
			Labels: map[string]string{
				clusterv1beta1.PlacementLabel: "placement1",
			},
		},
		Status: clusterv1beta1.PlacementDecisionStatus{
			Decisions: []clusterv1beta1.ClusterDecision{
				{ClusterName: "cluster1"},
			},
		},
	}

	placement2 := &clusterv1beta1.Placement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement2",
			Namespace: "open-cluster-management",
		},
	}

	placementDecision2 := &clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement2-decision-1",
			Namespace: "open-cluster-management",
			Labels: map[string]string{
				clusterv1beta1.PlacementLabel: "placement2",
			},
		},
		Status: clusterv1beta1.PlacementDecisionStatus{
			Decisions: []clusterv1beta1.ClusterDecision{
				{ClusterName: "cluster2"},
			},
		},
	}

	t.Run("Test handle MulticlusterRoleAssignment deletion", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(testscheme).WithObjects(
			testMra1, testMra2, testCp1, testCp2, placement1, placementDecision1, placement2, placementDecision2).Build()

		reconciler.Client = fakeClient
		reconciler.Scheme = testscheme

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
	for _, addToScheme := range []func(*runtime.Scheme) error{
		mrav1beta1.AddToScheme,
		clusterv1beta1.AddToScheme,
		corev1.AddToScheme,
	} {
		if err := addToScheme(testscheme); err != nil {
			t.Fatalf("AddToScheme error = %v", err)
		}
	}

	testMra := &mrav1beta1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multiclusterroleassignment-sample",
			Namespace: "open-cluster-management",
		},
		Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user1",
			},
			RoleAssignments: []mrav1beta1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement1", Namespace: "open-cluster-management"},
						},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement2", Namespace: "open-cluster-management"},
						},
					},
				},
			},
		},
	}

	placement1 := &clusterv1beta1.Placement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement1",
			Namespace: "open-cluster-management",
		},
	}

	placementDecision1 := &clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement1-decision-1",
			Namespace: "open-cluster-management",
			Labels: map[string]string{
				clusterv1beta1.PlacementLabel: "placement1",
			},
		},
		Status: clusterv1beta1.PlacementDecisionStatus{
			Decisions: []clusterv1beta1.ClusterDecision{
				{ClusterName: "cluster1"},
			},
		},
	}

	placement2 := &clusterv1beta1.Placement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement2",
			Namespace: "open-cluster-management",
		},
	}

	placementDecision2 := &clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "placement2-decision-1",
			Namespace: "open-cluster-management",
			Labels: map[string]string{
				clusterv1beta1.PlacementLabel: "placement2",
			},
		},
		Status: clusterv1beta1.PlacementDecisionStatus{
			Decisions: []clusterv1beta1.ClusterDecision{
				{ClusterName: "cluster2"},
			},
		},
	}

	t.Run("Test aggregateClusters", func(t *testing.T) {
		fakeClient := fake.NewClientBuilder().WithScheme(testscheme).WithObjects(
			testMra, placement1, placementDecision1, placement2, placementDecision2).
			WithStatusSubresource(&mrav1beta1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &mrav1beta1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(ctx, types.NamespacedName{Name: testMra.Name, Namespace: testMra.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
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

		clusters, _, err := reconciler.aggregateClusters(ctx, mra)
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

func TestUpdateStatus(t *testing.T) {
	// Comprehensive test for updateStatus() covering:
	// - Basic functionality (status updates, condition management)
	// - Role assignment initialization
	// - Ready condition calculation
	// - Conflict handling (single attempt, no retries)

	testscheme := scheme.Scheme
	for _, addToScheme := range []func(*runtime.Scheme) error{
		mrav1beta1.AddToScheme,
		cpv1alpha1.AddToScheme,
	} {
		if err := addToScheme(testscheme); err != nil {
			t.Fatalf("AddToScheme error = %v", err)
		}
	}

	testMra := &mrav1beta1.MulticlusterRoleAssignment{
		ObjectMeta: metav1.ObjectMeta{
			Name:            "test-update-status",
			Namespace:       "open-cluster-management",
			ResourceVersion: "1",
		},
		Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
			Subject: rbacv1.Subject{
				Kind: "User",
				Name: "test-user",
			},
			RoleAssignments: []mrav1beta1.RoleAssignment{
				{
					Name:        "test-assignment-1",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement1", Namespace: "open-cluster-management"},
						},
					},
				},
				{
					Name:        "test-assignment-2",
					ClusterRole: "test-role",
					ClusterSelection: mrav1beta1.ClusterSelection{
						Type: "placements",
						Placements: []mrav1beta1.PlacementRef{
							{Name: "placement2", Namespace: "open-cluster-management"},
						},
					},
				},
			},
		},
		Status: mrav1beta1.MulticlusterRoleAssignmentStatus{
			Conditions: []metav1.Condition{
				{
					Type:    string(mrav1beta1.ConditionTypeApplied),
					Status:  metav1.ConditionTrue,
					Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
					Message: "Applied successfully",
				},
			},
			RoleAssignments: []mrav1beta1.RoleAssignmentStatus{
				{
					Name:    "test-assignment-1",
					Status:  string(mrav1beta1.StatusTypeActive),
					Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
					Message: "Applied successfully",
				},
				{
					Name:    "test-assignment-2",
					Status:  string(mrav1beta1.StatusTypeActive),
					Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
					Message: "Applied successfully",
				},
			},
		},
	}

	t.Run("Should successfully update status and add Ready condition", func(t *testing.T) {
		// Create a fresh MRA object for this test
		mra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-update-status-simple",
				Namespace: "open-cluster-management",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment-1",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "placement1", Namespace: "open-cluster-management"},
							},
						},
					},
				},
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(mra).
			WithStatusSubresource(&mrav1beta1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		// Get the object from the fake client
		fetchedMra := &mrav1beta1.MulticlusterRoleAssignment{}
		objKey := client.ObjectKey{Name: mra.Name, Namespace: mra.Namespace}

		err := fakeClient.Get(context.TODO(), objKey, fetchedMra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Modify status to test update
		fetchedMra.Status.Conditions = []metav1.Condition{
			{
				Type:    string(mrav1beta1.ConditionTypeApplied),
				Status:  metav1.ConditionFalse,
				Reason:  string(mrav1beta1.ReasonApplyFailed),
				Message: "Custom application error",
			},
		}

		err = reconciler.updateStatus(context.TODO(), fetchedMra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify Ready condition was added by updateStatus
		foundReady := false
		for _, condition := range fetchedMra.Status.Conditions {
			if condition.Type == string(mrav1beta1.ConditionTypeReady) {
				foundReady = true
				break
			}
		}
		if !foundReady {
			t.Fatalf("Ready condition was not added by updateStatus")
		}

		// Verify custom condition was preserved
		appliedCondition := findConditionByType(fetchedMra.Status.Conditions, string(mrav1beta1.ConditionTypeApplied))
		if appliedCondition == nil {
			t.Fatalf("Applied condition not found")
		}
		if appliedCondition.Status != metav1.ConditionFalse {
			t.Fatalf("Expected Applied condition status to be False, got %s", appliedCondition.Status)
		}
		if appliedCondition.Message != "Custom application error" {
			t.Fatalf("Expected custom message to be preserved, got %s", appliedCondition.Message)
		}
	})

	t.Run("Should initialize role assignment statuses", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(testMraCopy).
			WithStatusSubresource(&mrav1beta1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &mrav1beta1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(context.TODO(), client.ObjectKey{
			Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Clear role assignment statuses to test initialization
		mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify role assignment statuses were initialized
		if len(mra.Status.RoleAssignments) != 2 {
			t.Fatalf("Expected 2 role assignment statuses, got %d", len(mra.Status.RoleAssignments))
		}

		for _, status := range mra.Status.RoleAssignments {
			if status.Status != string(mrav1beta1.StatusTypePending) {
				t.Fatalf("Expected role assignment status to be Pending, got %s", status.Status)
			}
			if status.Reason != string(mrav1beta1.ReasonProcessing) {
				t.Fatalf("Expected role assignment reason to be Initializing, got %s", status.Reason)
			}
		}
	})

	t.Run("Should calculate Ready condition as True when all assignments are Active", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()
		fakeClient := fake.NewClientBuilder().
			WithScheme(testscheme).
			WithObjects(testMraCopy).
			WithStatusSubresource(&mrav1beta1.MulticlusterRoleAssignment{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testscheme,
		}

		mra := &mrav1beta1.MulticlusterRoleAssignment{}
		err := fakeClient.Get(context.TODO(), client.ObjectKey{
			Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// Set conditions that should result in Ready=True
		mra.Status.Conditions = []metav1.Condition{
			{
				Type:    string(mrav1beta1.ConditionTypeApplied),
				Status:  metav1.ConditionTrue,
				Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
				Message: "Applied successfully",
			},
		}

		// Set all role assignments to Active
		mra.Status.RoleAssignments = []mrav1beta1.RoleAssignmentStatus{
			{
				Name:    "test-assignment-1",
				Status:  string(mrav1beta1.StatusTypeActive),
				Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
				Message: "Applied successfully",
			},
			{
				Name:    "test-assignment-2",
				Status:  string(mrav1beta1.StatusTypeActive),
				Reason:  string(mrav1beta1.ReasonSuccessfullyApplied),
				Message: "Applied successfully",
			},
		}

		err = reconciler.updateStatus(context.TODO(), mra)
		if err != nil {
			t.Fatalf("updateStatus error = %v", err)
		}

		// Verify Ready condition was set to True
		readyCondition := findConditionByType(mra.Status.Conditions, string(mrav1beta1.ConditionTypeReady))
		if readyCondition == nil {
			t.Fatalf("Ready condition not found")
		}
		if readyCondition.Status != metav1.ConditionTrue {
			t.Fatalf("Expected Ready condition status to be True, got %s", readyCondition.Status)
		}
		if readyCondition.Reason != string(mrav1beta1.ReasonAssignmentsReady) {
			t.Fatalf("Expected Ready condition reason to be AllApplied, got %s", readyCondition.Reason)
		}
	})

	t.Run("Should return conflict errors immediately without retries", func(t *testing.T) {
		testMraCopy := testMra.DeepCopy()

		// Mock client that always returns conflicts to verify no retry behavior
		mockClient := &MockConflictClient{
			Client: fake.NewClientBuilder().
				WithScheme(testscheme).
				WithObjects(testMraCopy).
				WithStatusSubresource(&mrav1beta1.MulticlusterRoleAssignment{}).
				Build(),
			conflictsToSimulate: 5, // Always conflicts
		}

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: mockClient,
			Scheme: testscheme,
		}

		mra := &mrav1beta1.MulticlusterRoleAssignment{}
		err := mockClient.Get(context.TODO(), client.ObjectKey{
			Name: testMraCopy.Name, Namespace: testMraCopy.Namespace}, mra)
		if err != nil {
			t.Fatalf("get MulticlusterRoleAssignment error = %v", err)
		}

		// This should fail immediately with conflict error (no retries)
		err = reconciler.updateStatus(context.TODO(), mra)
		if err == nil {
			t.Fatalf("Expected updateStatus to fail with conflict error")
		}

		// Verify it's a conflict error
		if !apierrors.IsConflict(err) {
			t.Fatalf("Expected conflict error, got: %v", err)
		}

		// Verify that exactly 1 attempt was made (confirms no retry logic)
		if mockClient.updateAttempts != 1 {
			t.Fatalf("Expected exactly 1 update attempt (no retries), got %d", mockClient.updateAttempts)
		}
	})
}

// MockConflictClient wraps a fake client to simulate optimistic concurrency conflicts
type MockConflictClient struct {
	client.Client
	conflictsToSimulate int
	updateAttempts      int
	statusConflict      bool
}

// Update simulates conflicts for regular updates
func (m *MockConflictClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if !m.statusConflict {
		m.updateAttempts++
		if m.updateAttempts <= m.conflictsToSimulate {
			return apierrors.NewConflict(
				schema.GroupResource{Group: "rbac.open-cluster-management.io", Resource: "multiclusterroleassignments"},
				obj.GetName(),
				fmt.Errorf("conflict during update"),
			)
		}
	}
	return m.Client.Update(ctx, obj, opts...)
}

// Status returns a mock status writer that simulates conflicts
func (m *MockConflictClient) Status() client.StatusWriter {
	return &MockStatusWriter{
		StatusWriter: m.Client.Status(),
		parent:       m,
	}
}

// MockErrorClient wraps a client to simulate various operation failures
type MockErrorClient struct {
	client.Client
	GetError          error
	UpdateError       error
	CreateError       error
	DeleteError       error
	StatusUpdateError error
	ShouldFail        bool
	ShouldFailGet     bool
	ShouldFailUpdate  bool
	ShouldFailCreate  bool
	ShouldFailDelete  bool
	ShouldFailStatus  bool
	TargetResource    string
}

func (m *MockErrorClient) Get(
	ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {

	if m.ShouldFailGet || (m.ShouldFail && m.TargetResource == "") {
		if m.TargetResource != "" {
			switch obj.(type) {
			case *clusterv1beta1.Placement:
				if m.TargetResource == "placements" {
					return m.GetError
				}
			}
		} else {
			return m.GetError
		}
	}
	return m.Client.Get(ctx, key, obj, opts...)
}

func (m *MockErrorClient) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if m.ShouldFailUpdate || m.ShouldFail {
		if m.TargetResource != "" {
			switch obj.(type) {
			case *mrav1beta1.MulticlusterRoleAssignment:
				if m.TargetResource == "multiclusterroleassignments" {
					return m.UpdateError
				}
			case *cpv1alpha1.ClusterPermission:
				if m.TargetResource == "clusterpermissions" {
					return m.UpdateError
				}
			}
		} else {
			return m.UpdateError
		}
	}
	return m.Client.Update(ctx, obj, opts...)
}

func (m *MockErrorClient) Create(ctx context.Context, obj client.Object, opts ...client.CreateOption) error {
	if m.ShouldFailCreate || m.ShouldFail {
		return m.CreateError
	}
	return m.Client.Create(ctx, obj, opts...)
}

func (m *MockErrorClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if m.ShouldFailDelete || m.ShouldFail {
		if m.TargetResource != "" {
			switch obj.(type) {
			case *cpv1alpha1.ClusterPermission:
				if m.TargetResource == "clusterpermissions" {
					return m.DeleteError
				}
			}
		} else {
			return m.DeleteError
		}
	}
	return m.Client.Delete(ctx, obj, opts...)
}

func (m *MockErrorClient) Status() client.StatusWriter {
	return &MockErrorStatusWriter{
		StatusWriter: m.Client.Status(),
		parent:       m,
	}
}

type MockErrorStatusWriter struct {
	client.StatusWriter
	parent *MockErrorClient
}

func (m *MockErrorStatusWriter) Update(
	ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {

	if m.parent.ShouldFailStatus {
		return m.parent.StatusUpdateError
	}
	return m.StatusWriter.Update(ctx, obj, opts...)
}

func (m *MockErrorStatusWriter) Patch(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {
	return m.StatusWriter.Patch(ctx, obj, patch, opts...)
}

// MockStatusWriter simulates optimistic concurrency conflicts for status updates
type MockStatusWriter struct {
	client.StatusWriter
	parent *MockConflictClient
}

// Update simulates conflicts for the first N attempts, then succeeds
func (m *MockStatusWriter) Update(ctx context.Context, obj client.Object,
	opts ...client.SubResourceUpdateOption) error {

	m.parent.updateAttempts++
	if m.parent.updateAttempts <= m.parent.conflictsToSimulate {
		errorMsg := "optimistic concurrency conflict"
		if m.parent.statusConflict {
			errorMsg = "status conflict during update"
		}
		return apierrors.NewConflict(
			schema.GroupResource{Group: "rbac.open-cluster-management.io", Resource: "multiclusterroleassignments"},
			obj.GetName(),
			fmt.Errorf("%s", errorMsg),
		)
	}

	// After the specified number of conflicts, succeed
	return m.StatusWriter.Update(ctx, obj, opts...)
}

// Patch delegates to the underlying status writer
func (m *MockStatusWriter) Patch(
	ctx context.Context, obj client.Object, patch client.Patch, opts ...client.SubResourcePatchOption) error {

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

func TestEnsureClusterPermissionAttemptDeleteLogic(t *testing.T) {
	var testScheme = scheme.Scheme
	for _, addToScheme := range []func(*runtime.Scheme) error{
		mrav1beta1.AddToScheme,
		clusterv1beta1.AddToScheme,
		cpv1alpha1.AddToScheme,
	} {
		if err := addToScheme(testScheme); err != nil {
			t.Fatalf("AddToScheme error = %v", err)
		}
	}

	t.Run("should delete ClusterPermission when both ClusterRoleBindings and RoleBindings are nil", func(t *testing.T) {
		// Create test MRA that doesn't target this cluster (will result in empty desired slice)
		testMra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mra",
				Namespace: "test-namespace",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "different-placement", Namespace: "test-namespace"},
							},
						},
					},
				},
			},
		}

		// Create existing ClusterPermission with no bindings
		existingCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: "test-cluster",
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{
				// Both fields are nil (default)
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(testMra, existingCP).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testScheme,
		}

		ctx := context.Background()

		roleAssignmentClusters := map[string][]string{
			"test-assignment": {},
		}

		err := reconciler.ensureClusterPermissionAttempt(ctx, testMra, "test-cluster", roleAssignmentClusters)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		var remainingCP cpv1alpha1.ClusterPermission
		err = fakeClient.Get(ctx, client.ObjectKey{Name: clusterPermissionManagedName, Namespace: "test-cluster"}, &remainingCP)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("Expected ClusterPermission to be deleted, but it still exists")
		}
	})

	t.Run("should delete ClusterPermission when both ClusterRoleBindings and RoleBindings are empty slices", func(t *testing.T) {
		testMra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mra",
				Namespace: "test-namespace",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "different-placement", Namespace: "test-namespace"},
							},
						},
					},
				},
			},
		}

		// Create existing ClusterPermission with empty slices
		emptyClusterRoleBindings := []cpv1alpha1.ClusterRoleBinding{}
		emptyRoleBindings := []cpv1alpha1.RoleBinding{}
		existingCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: "test-cluster",
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{
				ClusterRoleBindings: &emptyClusterRoleBindings,
				RoleBindings:        &emptyRoleBindings,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(testMra, existingCP).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testScheme,
		}

		ctx := context.Background()

		roleAssignmentClusters := map[string][]string{
			"test-assignment": {},
		}

		err := reconciler.ensureClusterPermissionAttempt(ctx, testMra, "test-cluster", roleAssignmentClusters)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		var remainingCP cpv1alpha1.ClusterPermission
		err = fakeClient.Get(ctx, client.ObjectKey{Name: clusterPermissionManagedName, Namespace: "test-cluster"}, &remainingCP)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("Expected ClusterPermission to be deleted, but it still exists")
		}
	})

	t.Run("should delete ClusterPermission when one field is nil and the other is empty", func(t *testing.T) {
		testMra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mra",
				Namespace: "test-namespace",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "different-placement", Namespace: "test-namespace"},
							},
						},
					},
				},
			},
		}

		// Create existing ClusterPermission with one nil and one empty slice
		emptyRoleBindings := []cpv1alpha1.RoleBinding{}
		existingCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: "test-cluster",
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{
				ClusterRoleBindings: nil,
				RoleBindings:        &emptyRoleBindings,
			},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(testMra, existingCP).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testScheme,
		}

		ctx := context.Background()

		roleAssignmentClusters := map[string][]string{
			"test-assignment": {},
		}

		err := reconciler.ensureClusterPermissionAttempt(ctx, testMra, "test-cluster", roleAssignmentClusters)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		var remainingCP cpv1alpha1.ClusterPermission
		err = fakeClient.Get(ctx, client.ObjectKey{Name: clusterPermissionManagedName, Namespace: "test-cluster"}, &remainingCP)
		if !apierrors.IsNotFound(err) {
			t.Fatalf("Expected ClusterPermission to be deleted, but it still exists")
		}
	})

	t.Run("should update ClusterPermission when bindings exist", func(t *testing.T) {
		testMra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mra",
				Namespace: "test-namespace",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "test-placement", Namespace: "test-namespace"},
							},
						},
					},
				},
			},
		}

		testPlacement := &clusterv1beta1.Placement{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-placement",
				Namespace: "test-namespace",
			},
		}

		testPlacementDecision := &clusterv1beta1.PlacementDecision{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-placement-decision-1",
				Namespace: "test-namespace",
				Labels: map[string]string{
					clusterv1beta1.PlacementLabel: "test-placement",
				},
			},
			Status: clusterv1beta1.PlacementDecisionStatus{
				Decisions: []clusterv1beta1.ClusterDecision{
					{ClusterName: "test-cluster"},
				},
			},
		}

		existingCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: "test-cluster",
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{},
		}

		fakeClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(testMra, testPlacement, testPlacementDecision, existingCP).
			WithStatusSubresource(&clusterv1beta1.PlacementDecision{}).
			Build()

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: fakeClient,
			Scheme: testScheme,
		}

		ctx := context.Background()

		roleAssignmentClusters := map[string][]string{
			"test-assignment": {"test-cluster"},
		}

		err := reconciler.ensureClusterPermissionAttempt(ctx, testMra, "test-cluster", roleAssignmentClusters)
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		var updatedCP cpv1alpha1.ClusterPermission
		err = fakeClient.Get(ctx, client.ObjectKey{Name: clusterPermissionManagedName, Namespace: "test-cluster"}, &updatedCP)
		if err != nil {
			t.Fatalf("Expected ClusterPermission to be updated, got error: %v", err)
		}

		if updatedCP.Spec.ClusterRoleBindings == nil || len(*updatedCP.Spec.ClusterRoleBindings) == 0 {
			t.Fatalf("Expected ClusterPermission to have ClusterRoleBindings")
		}
	})

	t.Run("should handle deletion errors gracefully", func(t *testing.T) {
		testMra := &mrav1beta1.MulticlusterRoleAssignment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-mra",
				Namespace: "test-namespace",
			},
			Spec: mrav1beta1.MulticlusterRoleAssignmentSpec{
				Subject: rbacv1.Subject{
					Kind: "User",
					Name: "test-user",
				},
				RoleAssignments: []mrav1beta1.RoleAssignment{
					{
						Name:        "test-assignment",
						ClusterRole: "test-role",
						ClusterSelection: mrav1beta1.ClusterSelection{
							Type: "placements",
							Placements: []mrav1beta1.PlacementRef{
								{Name: "different-placement", Namespace: "test-namespace"},
							},
						},
					},
				},
			},
		}

		existingCP := &cpv1alpha1.ClusterPermission{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterPermissionManagedName,
				Namespace: "test-cluster",
				Labels: map[string]string{
					clusterPermissionManagedByLabel: clusterPermissionManagedByValue,
				},
			},
			Spec: cpv1alpha1.ClusterPermissionSpec{},
		}

		type mockDeleteClient struct {
			client.Client
			deleteCallCount int
		}

		baseClient := fake.NewClientBuilder().
			WithScheme(testScheme).
			WithObjects(testMra, existingCP).
			Build()

		mock := &mockDeleteClient{
			Client: baseClient,
		}

		mock.Client = &clientWrapper{
			Client: baseClient,
			deleteFn: func(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
				mock.deleteCallCount++
				return fmt.Errorf("simulated deletion error")
			},
		}

		reconciler := &MulticlusterRoleAssignmentReconciler{
			Client: mock,
			Scheme: testScheme,
		}

		ctx := context.Background()

		roleAssignmentClusters := map[string][]string{
			"test-assignment": {},
		}

		err := reconciler.ensureClusterPermissionAttempt(ctx, testMra, "test-cluster", roleAssignmentClusters)
		if err == nil {
			t.Fatalf("Expected deletion error to be returned")
		}
		if err.Error() != "simulated deletion error" {
			t.Fatalf("Expected 'simulated deletion error', got: %v", err)
		}

		if mock.deleteCallCount != 1 {
			t.Fatalf("Expected 1 deletion attempt, got: %d", mock.deleteCallCount)
		}
	})
}

// clientWrapper is a helper struct to override specific client methods for testing
type clientWrapper struct {
	client.Client
	deleteFn func(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error
	updateFn func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error
}

func (c *clientWrapper) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if c.deleteFn != nil {
		return c.deleteFn(ctx, obj, opts...)
	}
	return c.Client.Delete(ctx, obj, opts...)
}

func (c *clientWrapper) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if c.updateFn != nil {
		return c.updateFn(ctx, obj, opts...)
	}
	return c.Client.Update(ctx, obj, opts...)
}

func createTestPlacement(ctx context.Context, k8sClient client.Client, name string) error {
	placement := &clusterv1beta1.Placement{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: multiclusterRoleAssignmentNamespace,
		},
		Spec: clusterv1beta1.PlacementSpec{
			Predicates: []clusterv1beta1.ClusterPredicate{
				{
					RequiredClusterSelector: clusterv1beta1.ClusterSelector{
						LabelSelector: metav1.LabelSelector{},
					},
				},
			},
		},
	}
	return k8sClient.Create(ctx, placement)
}

func createTestPlacementDecision(ctx context.Context, k8sClient client.Client, placementDecisionNameSuffix string,
	placementName string, clusters []string) error {

	decisions := make([]clusterv1beta1.ClusterDecision, len(clusters))
	for i, cluster := range clusters {
		decisions[i] = clusterv1beta1.ClusterDecision{
			ClusterName: cluster,
		}
	}

	pd := &clusterv1beta1.PlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      placementName + "-" + placementDecisionNameSuffix,
			Namespace: multiclusterRoleAssignmentNamespace,
			Labels: map[string]string{
				clusterv1beta1.PlacementLabel: placementName,
			},
		},
	}

	if err := k8sClient.Create(ctx, pd); err != nil {
		return err
	}

	pd.Status = clusterv1beta1.PlacementDecisionStatus{
		Decisions: decisions,
	}
	return k8sClient.Status().Update(ctx, pd)
}
