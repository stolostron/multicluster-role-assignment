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

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stolostron/multicluster-role-assignment/test/utils"

	mrav1beta1 "github.com/stolostron/multicluster-role-assignment/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cpv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"
)

const (
	clusterPermissionManagedName = "mra-managed-permissions"
	managedCluster01             = "managedcluster01"
	managedCluster02             = "managedcluster02"
	placementCluster01           = "placement-cluster-01"
	placementCluster01And02      = "placement-cluster-01-02"
	placementCluster02           = "placement-cluster-02"
)

// registerClusterPermissionValidationSpecs adds ClusterPermission spec.validate and
// ClusterRole-existence status coverage to the Manager Ordered suite. Kind has no
// ClusterPermission operator, so validation conditions are patched onto CP status.
func registerClusterPermissionValidationSpecs() {
	Context("ClusterPermission ClusterRole validation", func() {
		Context("always sets ClusterPermission spec.validate=true", func() {
			const (
				mraName        = "test-mra-cp-validate-flag"
				assignmentName = "validate-flag-assignment"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster01})
			})

			It("should set spec.validate=true on a newly created ClusterPermission", func() {
				createMRAWithClusterRole(mraName, "test-user-cp-validate-flag",
					assignmentName, "view", placementCluster01, nil)

				cp := waitForManagedClusterPermission(managedCluster01)
				Expect(cp.Spec.Validate).NotTo(BeNil())
				Expect(*cp.Spec.Validate).To(BeTrue())
			})
		})

		Context("sets spec.validate=true for namespaced RoleBindings", func() {
			const (
				mraName        = "test-mra-cp-validate-flag-rb"
				assignmentName = "validate-flag-rb-assignment"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster02})
			})

			It("should set spec.validate=true when the assignment uses targetNamespaces", func() {
				createMRAWithClusterRole(mraName, "test-user-cp-validate-flag-rb",
					assignmentName, "edit", placementCluster02, []string{"default"})

				cp := waitForManagedClusterPermission(managedCluster02)
				Expect(cp.Spec.Validate).NotTo(BeNil())
				Expect(*cp.Spec.Validate).To(BeTrue())
				Expect(cp.Spec.RoleBindings).NotTo(BeNil())
			})
		})

		Context("restores spec.validate=true when updating an existing ClusterPermission", func() {
			const (
				mraNameA        = "test-mra-cp-validate-restore-a"
				mraNameB        = "test-mra-cp-validate-restore-b"
				assignmentNameA = "validate-restore-assignment-a"
				assignmentNameB = "validate-restore-assignment-b"
			)

			AfterAll(func() {
				cleanupTestResources(mraNameA, []string{managedCluster01})
				cleanupTestResources(mraNameB, []string{managedCluster01})
			})

			It("should set spec.validate=true again when another MRA updates the shared ClusterPermission", func() {
				createMRAWithClusterRole(mraNameA, "test-user-cp-validate-restore-a",
					assignmentNameA, "view", placementCluster01, nil)
				_ = waitForManagedClusterPermission(managedCluster01)

				By("clearing spec.validate to simulate a pre-validation ClusterPermission")
				cmd := exec.Command("kubectl", "patch", "clusterpermission", clusterPermissionManagedName,
					"-n", managedCluster01, "--type=merge", "-p", `{"spec":{"validate":false}}`)
				_, err := utils.Run(cmd)
				Expect(err).NotTo(HaveOccurred())

				createMRAWithClusterRole(mraNameB, "test-user-cp-validate-restore-b",
					assignmentNameB, "admin", placementCluster01, nil)

				Eventually(func(g Gomega) {
					cp := getManagedClusterPermission(managedCluster01)
					g.Expect(cp.Spec.Validate).NotTo(BeNil())
					g.Expect(*cp.Spec.Validate).To(BeTrue())
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		Context("ClusterRole present on all selected clusters", func() {
			const (
				mraName        = "test-mra-role-on-both"
				assignmentName = "role-on-both-assignment"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster01, managedCluster02})
			})

			It("should become Active when validation succeeds on every cluster", func() {
				createMRAWithClusterRole(mraName, "test-user-role-on-both",
					assignmentName, "view", placementCluster01And02, nil)
				waitForMRA(mraName)

				Eventually(func(g Gomega) {
					mra := getMRA(mraName)
					ra := roleAssignmentByName(mra, assignmentName)
					g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypeActive)))
					ready := findCondition(mra.Status.Conditions, string(mrav1beta1.ConditionTypeReady))
					g.Expect(ready).NotTo(BeNil())
					g.Expect(ready.Status).To(Equal(metav1.ConditionTrue))
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		Context("ClusterRole missing on one selected cluster", func() {
			const (
				mraName        = "test-mra-role-on-one"
				assignmentName = "role-on-one-assignment"
				missingRole    = "test-cluster-role-scenario1"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster01, managedCluster02})
			})

			It("should report Error for the cluster where the ClusterRole is missing", Label("allows-errors"), func() {
				createMRAWithClusterRole(mraName, "test-user-role-on-one",
					assignmentName, missingRole, placementCluster01And02, nil)
				waitForMRA(mraName)

				setClusterPermissionValidation(managedCluster01, metav1.ConditionTrue,
					"AllClusterRolesFound", "All referenced cluster roles exist")
				setClusterPermissionValidation(managedCluster02, metav1.ConditionFalse,
					"ClusterRolesNotFound",
					fmt.Sprintf("The following cluster roles were not found: %s", missingRole))

				Eventually(func(g Gomega) {
					mra := getMRA(mraName)
					ra := roleAssignmentByName(mra, assignmentName)
					g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
					g.Expect(ra.Message).To(ContainSubstring(missingRole))
					g.Expect(ra.Message).To(ContainSubstring(managedCluster02))
					g.Expect(ra.Message).NotTo(ContainSubstring(
						fmt.Sprintf("ClusterRole %q was not found on cluster %s", missingRole, managedCluster01)))
					ready := findCondition(mra.Status.Conditions, string(mrav1beta1.ConditionTypeReady))
					g.Expect(ready).NotTo(BeNil())
					g.Expect(ready.Status).To(Equal(metav1.ConditionFalse))
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		Context("ClusterRole missing on all selected clusters", func() {
			const (
				mraName        = "test-mra-role-on-none"
				assignmentName = "role-on-none-assignment"
				missingRole    = "missing-cr-e2e-none"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster01, managedCluster02})
			})

			It("should report Error on every selected cluster", Label("allows-errors"), func() {
				createMRAWithClusterRole(mraName, "test-user-role-on-none",
					assignmentName, missingRole, placementCluster01And02, nil)
				waitForMRA(mraName)

				msg := fmt.Sprintf("The following cluster roles were not found: %s", missingRole)
				setClusterPermissionValidation(managedCluster01, metav1.ConditionFalse, "ClusterRolesNotFound", msg)
				setClusterPermissionValidation(managedCluster02, metav1.ConditionFalse, "ClusterRolesNotFound", msg)

				Eventually(func(g Gomega) {
					mra := getMRA(mraName)
					ra := roleAssignmentByName(mra, assignmentName)
					g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
					g.Expect(ra.Message).To(ContainSubstring(managedCluster01))
					g.Expect(ra.Message).To(ContainSubstring(managedCluster02))
					g.Expect(ra.Message).To(ContainSubstring(missingRole))
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		Context("namespaced RoleBinding ClusterRole validation", func() {
			const (
				mraName        = "test-mra-validate-missing-cr-rb"
				assignmentName = "missing-cr-rb-assignment"
				missingRole    = "missing-cr-e2e-rb"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster02})
			})

			It("should report Error when a namespaced assignment references a missing ClusterRole",
				Label("allows-errors"), func() {
					createMRAWithClusterRole(mraName, "test-user-validate-missing-cr-rb",
						assignmentName, missingRole, placementCluster02, []string{"default"})
					waitForMRA(mraName)

					setClusterPermissionValidation(managedCluster02, metav1.ConditionFalse,
						"ClusterRolesNotFound",
						fmt.Sprintf("The following cluster roles were not found: %s", missingRole))

					Eventually(func(g Gomega) {
						mra := getMRA(mraName)
						ra := roleAssignmentByName(mra, assignmentName)
						g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
						g.Expect(ra.Message).To(ContainSubstring(missingRole))
						g.Expect(ra.Message).To(ContainSubstring(managedCluster02))
					}, 30*time.Second, 1*time.Second).Should(Succeed())
				})
		})

		Context("shared ClusterPermission validation is attributed per ClusterRole", func() {
			const (
				mraValidName   = "test-mra-validate-other-role"
				mraMissingName = "test-mra-validate-other-role-missing"
				validRAName    = "valid-shared-assignment"
				missingRAName  = "missing-shared-assignment"
				missingRole    = "does-not-exist-shared"
			)

			AfterAll(func() {
				cleanupTestResources(mraValidName, []string{managedCluster01})
				cleanupTestResources(mraMissingName, []string{managedCluster01})
			})

			It("should fail only the assignment whose ClusterRole is listed as missing", Label("allows-errors"), func() {
				createMRAWithClusterRole(mraValidName, "test-user-validate-other-valid",
					validRAName, "view", placementCluster01, nil)
				createMRAWithClusterRole(mraMissingName, "test-user-validate-other-missing",
					missingRAName, missingRole, placementCluster01, nil)
				waitForMRA(mraValidName)
				waitForMRA(mraMissingName)

				setClusterPermissionValidation(managedCluster01, metav1.ConditionFalse,
					"ClusterRolesNotFound",
					fmt.Sprintf("The following cluster roles were not found: %s", missingRole))

				Eventually(func(g Gomega) {
					validMRA := getMRA(mraValidName)
					g.Expect(roleAssignmentByName(validMRA, validRAName).Status).
						To(Equal(string(mrav1beta1.StatusTypeActive)))

					missingMRA := getMRA(mraMissingName)
					missingRA := roleAssignmentByName(missingMRA, missingRAName)
					g.Expect(missingRA.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
					g.Expect(missingRA.Message).To(ContainSubstring(missingRole))
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})

		Context("validation condition changes trigger MRA reconcile", func() {
			const (
				mraName        = "test-mra-validate-pending"
				assignmentName = "pending-validation-assignment"
				missingRole    = "missing-cr-e2e-pending"
			)

			AfterAll(func() {
				cleanupTestResources(mraName, []string{managedCluster01})
			})

			It("should move from Pending to Error when ValidateClusterRolesExist becomes False", Label("allows-errors"), func() {
				createMRAWithClusterRole(mraName, "test-user-validate-pending",
					assignmentName, missingRole, placementCluster01, nil)
				waitForMRA(mraName)

				By("marking ClusterRole validation as not yet reported")
				setClusterPermissionValidation(managedCluster01, metav1.ConditionUnknown,
					"ValidationInProgress", "ClusterRole validation has not completed")

				Eventually(func(g Gomega) {
					mra := getMRA(mraName)
					ra := roleAssignmentByName(mra, assignmentName)
					g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypePending)))
					g.Expect(ra.Message).To(ContainSubstring("ClusterRole validation pending"))
				}, 30*time.Second, 1*time.Second).Should(Succeed())

				By("reporting that the ClusterRole does not exist")
				setClusterPermissionValidation(managedCluster01, metav1.ConditionFalse,
					"ClusterRolesNotFound",
					fmt.Sprintf("The following cluster roles were not found: %s", missingRole))

				Eventually(func(g Gomega) {
					mra := getMRA(mraName)
					ra := roleAssignmentByName(mra, assignmentName)
					g.Expect(ra.Status).To(Equal(string(mrav1beta1.StatusTypeError)))
					g.Expect(ra.Message).To(ContainSubstring(missingRole))
					g.Expect(ra.Message).To(ContainSubstring("was not found"))
				}, 30*time.Second, 1*time.Second).Should(Succeed())
			})
		})
	})
}

func createMRAWithClusterRole(
	mraName, userName, assignmentName, clusterRole, placementName string, targetNamespaces []string,
) {
	targetYAML := ""
	if len(targetNamespaces) > 0 {
		targetYAML = "      targetNamespaces:\n"
		for _, ns := range targetNamespaces {
			targetYAML += fmt.Sprintf("      - %s\n", ns)
		}
	}

	mraYAML := fmt.Sprintf(`apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: %s
  namespace: %s
spec:
  subject:
    kind: User
    name: %s
    apiGroup: rbac.authorization.k8s.io
  roleAssignments:
    - name: %s
      clusterRole: %s
%s      clusterSelection:
        type: placements
        placements:
          - name: %s
            namespace: %s
`, mraName, openClusterManagementGlobalSetNamespace, userName, assignmentName, clusterRole, targetYAML,
		placementName, openClusterManagementGlobalSetNamespace)

	mraFile := fmt.Sprintf("/tmp/%s.yaml", mraName)
	err := os.WriteFile(mraFile, []byte(mraYAML), 0644)
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command("kubectl", "apply", "-f", mraFile)
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
	waitForController()
}

func waitForManagedClusterPermission(clusterName string) cpv1alpha1.ClusterPermission {
	var cp cpv1alpha1.ClusterPermission
	Eventually(func(g Gomega) {
		cp = getManagedClusterPermission(clusterName)
		g.Expect(cp.Name).To(Equal(clusterPermissionManagedName))
	}, 2*time.Minute, 1*time.Second).Should(Succeed())
	return cp
}

func getManagedClusterPermission(clusterName string) cpv1alpha1.ClusterPermission {
	cpJSON := fetchK8sResourceJSON("clusterpermissions", clusterPermissionManagedName, clusterName)
	var cp cpv1alpha1.ClusterPermission
	unmarshalJSON(cpJSON, &cp)
	return cp
}

func getMRA(mraName string) mrav1beta1.MulticlusterRoleAssignment {
	mraJSON := fetchK8sResourceJSON("multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
	var mra mrav1beta1.MulticlusterRoleAssignment
	unmarshalJSON(mraJSON, &mra)
	return mra
}

func roleAssignmentByName(mra mrav1beta1.MulticlusterRoleAssignment, name string) mrav1beta1.RoleAssignmentStatus {
	for _, ra := range mra.Status.RoleAssignments {
		if ra.Name == name {
			return ra
		}
	}
	Fail(fmt.Sprintf("role assignment %s not found on MRA %s", name, mra.Name))
	return mrav1beta1.RoleAssignmentStatus{}
}

func setClusterPermissionValidation(clusterName string, status metav1.ConditionStatus, reason, message string) {
	Eventually(func() error {
		cpJSON := fetchK8sResourceJSON("clusterpermissions", clusterPermissionManagedName, clusterName)
		var cp cpv1alpha1.ClusterPermission
		unmarshalJSON(cpJSON, &cp)
		setClusterPermissionCondition(&cp, cpv1alpha1.ConditionTypeValidateClusterRolesExist, status, reason, message)

		cpBytes, err := json.Marshal(cp)
		if err != nil {
			return err
		}
		tmpFile := fmt.Sprintf("/tmp/%s-%s-validation-status.json", clusterPermissionManagedName, clusterName)
		if err := os.WriteFile(tmpFile, cpBytes, 0644); err != nil {
			return err
		}
		cmd := exec.Command("kubectl", "apply", "-f", tmpFile, "--subresource=status", "--server-side")
		_, err = utils.Run(cmd)
		return err
	}, 30*time.Second, 1*time.Second).Should(Succeed())
	waitForController()
}

func setClusterPermissionCondition(
	cp *cpv1alpha1.ClusterPermission, condType string, status metav1.ConditionStatus, reason, message string,
) {
	cond := metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		LastTransitionTime: metav1.Now(),
	}
	for i := range cp.Status.Conditions {
		if cp.Status.Conditions[i].Type == condType {
			cp.Status.Conditions[i] = cond
			return
		}
	}
	cp.Status.Conditions = append(cp.Status.Conditions, cond)
}
