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
	"path/filepath"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterpermissionv1alpha1 "open-cluster-management.io/cluster-permission/api/v1alpha1"

	rbacv1alpha1 "github.com/stolostron/multicluster-role-assignment/api/v1alpha1"
	"github.com/stolostron/multicluster-role-assignment/test/utils"
)

// namespace where the project is deployed in
const namespace = "multicluster-role-assignment-system"

// serviceAccountName created for the project
const serviceAccountName = "multicluster-role-assignment-controller-manager"

// metricsServiceName is the name of the metrics service of the project
const metricsServiceName = "multicluster-role-assignment-controller-manager-metrics-service"

// metricsRoleBindingName is the name of the RBAC that will be created to allow get the metrics data
const metricsRoleBindingName = "multicluster-role-assignment-metrics-binding"

// openClusterManagementGlobalSetNamespace is the namespace for all MulticlusterRoleAssignments
const openClusterManagementGlobalSetNamespace = "open-cluster-management-global-set"

// testMulticlusterRoleAssignmentSingleCRBName is the name of the test MulticlusterRoleAssignment with a single cluster
// role binding single assignment
const testMulticlusterRoleAssignmentSingleCRBName = "test-multicluster-role-assignment-single-clusterrolebinding"

// testMulticlusterRoleAssignmentSingleRBName is the name of the test MulticlusterRoleAssignment with a single
// role binding single assignment
const testMulticlusterRoleAssignmentSingleRBName = "test-multicluster-role-assignment-single-rolebinding"

// testMulticlusterRoleAssignmentMultipleName is the name of the test MulticlusterRoleAssignment with multiple mixed
// assignments - #1
const testMulticlusterRoleAssignmentMultiple1Name = "test-multicluster-role-assignment-multiple-1"

// testMulticlusterRoleAssignmentMultipleName is the name of the test MulticlusterRoleAssignment with multiple mixed
// assignments - #2
const testMulticlusterRoleAssignmentMultiple2Name = "test-multicluster-role-assignment-multiple-2"

var _ = Describe("Manager", Ordered, func() {
	var controllerPodName string

	// Before running the tests, set up the environment by creating the namespace,
	// enforce the restricted security policy to the namespace, installing CRDs,
	// and deploying the controller.
	BeforeAll(func() {
		By("creating manager namespace")
		cmd := exec.Command("kubectl", "create", "ns", namespace)
		_, err := utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to create namespace")

		By("labeling the namespace to enforce the restricted security policy")
		cmd = exec.Command("kubectl", "label", "--overwrite", "ns", namespace,
			"pod-security.kubernetes.io/enforce=restricted")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to label namespace with restricted policy")

		By("installing CRDs")
		cmd = exec.Command("make", "install")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to install CRDs")

		By("installing the external CRDs required for all tests")
		cmd = exec.Command("kubectl", "apply", "-f", "test/crd/")
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating the %s namespace", openClusterManagementGlobalSetNamespace))
		cmd = exec.Command("kubectl", "create", "ns", openClusterManagementGlobalSetNamespace)
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred())

		By("creating managed cluster namespaces and ManagedClusters")
		for i := 1; i <= 3; i++ {
			clusterName := fmt.Sprintf("managedcluster%02d", i)

			By(fmt.Sprintf("creating the %s namespace", clusterName))
			cmd = exec.Command("kubectl", "create", "ns", clusterName)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())

			By(fmt.Sprintf("creating ManagedCluster %s", clusterName))
			managedClusterTemplate, err := os.ReadFile("test/testdata/managedcluster-template.yaml")
			Expect(err).NotTo(HaveOccurred())

			managedCluster := strings.ReplaceAll(
				string(managedClusterTemplate), "CLUSTER_NAME_PLACEHOLDER", clusterName)
			managedClusterFile := fmt.Sprintf("/tmp/%s.yaml", clusterName)
			err = os.WriteFile(managedClusterFile, []byte(managedCluster), os.FileMode(0o644))
			Expect(err).NotTo(HaveOccurred())

			cmd = exec.Command("kubectl", "apply", "-f", managedClusterFile)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred())
		}

		By("deploying the controller-manager")
		cmd = exec.Command("make", "deploy", fmt.Sprintf("IMG=%s", projectImage))
		_, err = utils.Run(cmd)
		Expect(err).NotTo(HaveOccurred(), "Failed to deploy the controller-manager")
	})

	// After all tests have been executed, clean up by undeploying the controller, uninstalling CRDs,
	// and deleting the namespace.
	AfterAll(func() {
		By("cleaning up the curl pod for metrics")
		cmd := exec.Command("kubectl", "delete", "pod", "curl-metrics", "-n", namespace)
		_, _ = utils.Run(cmd)

		By("cleaning up managed clusters and namespaces")
		for i := 1; i <= 3; i++ {
			clusterName := fmt.Sprintf("managedcluster%02d", i)
			managedClusterFile := fmt.Sprintf("/tmp/%s.yaml", clusterName)

			cmd := exec.Command("kubectl", "delete", "-f", managedClusterFile)
			_, _ = utils.Run(cmd)

			cmd = exec.Command("kubectl", "delete", "ns", clusterName)
			_, _ = utils.Run(cmd)
		}

		By(fmt.Sprintf("cleaning up %s namespace", openClusterManagementGlobalSetNamespace))
		cmd = exec.Command("kubectl", "delete", "ns", openClusterManagementGlobalSetNamespace)
		_, _ = utils.Run(cmd)

		By("undeploying the controller-manager")
		cmd = exec.Command("make", "undeploy")
		_, _ = utils.Run(cmd)

		By("uninstalling CRDs")
		cmd = exec.Command("make", "uninstall")
		_, _ = utils.Run(cmd)

		By("removing manager namespace")
		cmd = exec.Command("kubectl", "delete", "ns", namespace)
		_, _ = utils.Run(cmd)
	})

	AfterEach(func() {
		specReport := CurrentSpecReport()

		// Skip error checking for tests that expect controller errors. To skip error checking for a specific test, add
		// the "allows-errors" label: It("should handle invalid input", Label("allows-errors"), func() { ... }). Since
		// error logs will remain in the controller logs from all tests, we should put expected error tests at the end
		// of all success tests, or we have to rethink how we check for errors.
		if !slices.Contains(specReport.Labels(), "allows-errors") {
			By("Checking controller logs for errors")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				lowerLogs := strings.ToLower(controllerLogs)
				// Set max length to 0 for this specific assertion to avoid truncation
				originalMaxLength := format.MaxLength
				format.MaxLength = 0
				Expect(lowerLogs).NotTo(ContainSubstring("error"), "Controller logs should not contain errors")
				format.MaxLength = originalMaxLength
			}
		}

		// After each test, check for failures and collect logs, events, and pod descriptions for debugging.
		if specReport.Failed() {
			By("Fetching controller manager pod logs")
			cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
			controllerLogs, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Controller logs:\n %s", controllerLogs)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Controller logs: %s", err)
			}

			By("Fetching Kubernetes events")
			cmd = exec.Command("kubectl", "get", "events", "-n", namespace, "--sort-by=.lastTimestamp")
			eventsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Kubernetes events:\n%s", eventsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get Kubernetes events: %s", err)
			}

			By("Fetching curl-metrics logs")
			cmd = exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
			metricsOutput, err := utils.Run(cmd)
			if err == nil {
				_, _ = fmt.Fprintf(GinkgoWriter, "Metrics logs:\n %s", metricsOutput)
			} else {
				_, _ = fmt.Fprintf(GinkgoWriter, "Failed to get curl-metrics logs: %s", err)
			}

			By("Fetching controller manager pod description")
			cmd = exec.Command("kubectl", "describe", "pod", controllerPodName, "-n", namespace)
			podDescription, err := utils.Run(cmd)
			if err == nil {
				fmt.Println("Pod description:\n", podDescription)
			} else {
				fmt.Println("Failed to describe controller pod")
			}
		}
	})

	SetDefaultEventuallyTimeout(2 * time.Minute)
	SetDefaultEventuallyPollingInterval(time.Second)

	Context("Manager", func() {
		It("should run successfully", func() {
			By("validating that the controller-manager pod is running as expected")
			verifyControllerUp := func(g Gomega) {
				// Get the name of the controller-manager pod
				cmd := exec.Command("kubectl", "get",
					"pods", "-l", "control-plane=controller-manager",
					"-o", "go-template={{ range .items }}"+
						"{{ if not .metadata.deletionTimestamp }}"+
						"{{ .metadata.name }}"+
						"{{ \"\\n\" }}{{ end }}{{ end }}",
					"-n", namespace,
				)

				podOutput, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred(), "Failed to retrieve controller-manager pod information")
				podNames := utils.GetNonEmptyLines(podOutput)
				g.Expect(podNames).To(HaveLen(1), "expected 1 controller pod running")
				controllerPodName = podNames[0]
				g.Expect(controllerPodName).To(ContainSubstring("controller-manager"))

				// Validate the pod's status
				cmd = exec.Command("kubectl", "get",
					"pods", controllerPodName, "-o", "jsonpath={.status.phase}",
					"-n", namespace,
				)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Running"), "Incorrect controller-manager pod status")
			}
			Eventually(verifyControllerUp).Should(Succeed())
		})

		It("should ensure the metrics endpoint is serving metrics", func() {
			By("creating a ClusterRoleBinding for the service account to allow access to metrics")
			cmd := exec.Command("kubectl", "create", "clusterrolebinding", metricsRoleBindingName,
				"--clusterrole=multicluster-role-assignment-metrics-reader",
				fmt.Sprintf("--serviceaccount=%s:%s", namespace, serviceAccountName),
			)
			_, err := utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create ClusterRoleBinding")

			By("validating that the metrics service is available")
			cmd = exec.Command("kubectl", "get", "service", metricsServiceName, "-n", namespace)
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Metrics service should exist")

			By("getting the service account token")
			token, err := serviceAccountToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			By("waiting for the metrics endpoint to be ready")
			verifyMetricsEndpointReady := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "endpoints", metricsServiceName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("8443"), "Metrics endpoint is not ready")
			}
			Eventually(verifyMetricsEndpointReady).Should(Succeed())

			By("verifying that the controller manager is serving the metrics server")
			verifyMetricsServerStarted := func(g Gomega) {
				cmd := exec.Command("kubectl", "logs", controllerPodName, "-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(ContainSubstring("controller-runtime.metrics\tServing metrics server"),
					"Metrics server not yet started")
			}
			Eventually(verifyMetricsServerStarted).Should(Succeed())

			By("creating the curl-metrics pod to access the metrics endpoint")
			cmd = exec.Command("kubectl", "run", "curl-metrics", "--restart=Never",
				"--namespace", namespace,
				"--image=curlimages/curl:latest",
				"--overrides",
				fmt.Sprintf(`{
					"spec": {
						"containers": [{
							"name": "curl",
							"image": "curlimages/curl:latest",
							"command": ["/bin/sh", "-c"],
							"args": ["curl -v -k -H 'Authorization: Bearer %s' https://%s.%s.svc.cluster.local:8443/metrics"],
							"securityContext": {
								"readOnlyRootFilesystem": true,
								"allowPrivilegeEscalation": false,
								"capabilities": {
									"drop": ["ALL"]
								},
								"runAsNonRoot": true,
								"runAsUser": 1000,
								"seccompProfile": {
									"type": "RuntimeDefault"
								}
							}
						}],
						"serviceAccountName": "%s"
					}
				}`, token, metricsServiceName, namespace, serviceAccountName))
			_, err = utils.Run(cmd)
			Expect(err).NotTo(HaveOccurred(), "Failed to create curl-metrics pod")

			By("waiting for the curl-metrics pod to complete.")
			verifyCurlUp := func(g Gomega) {
				cmd := exec.Command("kubectl", "get", "pods", "curl-metrics",
					"-o", "jsonpath={.status.phase}",
					"-n", namespace)
				output, err := utils.Run(cmd)
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(output).To(Equal("Succeeded"), "curl pod in wrong status")
			}
			Eventually(verifyCurlUp, 5*time.Minute).Should(Succeed())

			By("getting the metrics by checking curl-metrics logs")
			metricsOutput := getMetricsOutput()
			Expect(metricsOutput).To(ContainSubstring(
				"controller_runtime_reconcile_total",
			))
		})

		// +kubebuilder:scaffold:e2e-webhooks-checks

		Context("should create single ClusterPermission with single ClusterRoleBinding when "+
			"MulticlusterRoleAssignment is created", func() {

			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("resource creation and fetching", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create and fetch MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with one RoleAssignment")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml")

					By("waiting for controller to process the MulticlusterRoleAssignment")
					time.Sleep(2 * time.Second)

					By("waiting for MulticlusterRoleAssignment to be created and fetching it")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleCRBName, openClusterManagementGlobalSetNamespace)

					By("unmarshaling MulticlusterRoleAssignment json")
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch ClusterPermission", func() {
					By("waiting for ClusterPermission to be created and fetching it")
					clusterPermissionJSON = fetchK8sResourceJSON("clusterpermissions",
						"mra-managed-permissions", "managedcluster01")

					By("unmarshaling ClusterPermission json")
					unmarshalJSON(clusterPermissionJSON, &clusterPermission)
				})
			})

			Context("ClusterPermission validation", func() {
				It("should have correct ClusterRoleBinding", func() {
					By("verifying ClusterPermission has correct ClusterRoleBinding")
					Expect(*clusterPermission.Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermission.Spec.RoleBindings).To(BeNil())

					expectedBindings := []ExpectedBinding{
						{RoleName: "view", Namespace: ""},
					}
					validateClusterPermissionBindings(
						clusterPermission, "test-user-single-clusterrolebinding", expectedBindings)
				})
			})

			Context("MulticlusterRoleAssignment status validation", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment status", func() {
					By("verifying role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(1))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "test-role-assignment")
				})
			})
		})

		Context("should create single ClusterPermission with single RoleBinding when MulticlusterRoleAssignment "+
			"is created", func() {

			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleRBName, []string{"managedcluster02"})
			})

			Context("resource creation and fetching", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create and fetch MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with one namespaced RoleAssignment")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_2.yaml")

					By("waiting for controller to process the MulticlusterRoleAssignment")
					time.Sleep(2 * time.Second)

					By("waiting for MulticlusterRoleAssignment to be created and fetching it")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleRBName, openClusterManagementGlobalSetNamespace)

					By("unmarshaling MulticlusterRoleAssignment json")
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch ClusterPermission", func() {
					By("waiting for ClusterPermission to be created and fetching it")
					clusterPermissionJSON = fetchK8sResourceJSON("clusterpermissions",
						"mra-managed-permissions", "managedcluster02")

					By("unmarshaling ClusterPermission json")
					unmarshalJSON(clusterPermissionJSON, &clusterPermission)
				})
			})

			Context("ClusterPermission validation", func() {
				It("should have correct RoleBindings", func() {
					By("verifying ClusterPermission has correct RoleBindings")
					Expect(clusterPermission.Spec.ClusterRoleBindings).To(BeNil())
					Expect(clusterPermission.Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermission.Spec.RoleBindings).To(HaveLen(5))

					expectedBindings := []ExpectedBinding{
						{RoleName: "edit", Namespace: "default"},
						{RoleName: "edit", Namespace: "kube-system"},
						{RoleName: "edit", Namespace: "monitoring"},
						{RoleName: "edit", Namespace: "observability"},
						{RoleName: "edit", Namespace: "logging"},
					}
					validateClusterPermissionBindings(
						clusterPermission, "test-user-single-rolebinding", expectedBindings)
				})
			})

			Context("MulticlusterRoleAssignment status validation", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment status", func() {
					By("verifying role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(1))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "test-role-assignment-namespaced")
				})
			})
		})

		Context("should create multiple ClusterPermissions across different clusters", func() {
			var clusterPermission01, clusterPermission02,
				clusterPermission03 clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple1Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
			})

			Context("resource creation and fetching", func() {
				var mraJSON string
				var clusterPermissionJSONs [3]string

				It("should create and fetch MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with multiple RoleAssignments")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_1.yaml")

					By("waiting for controller to process the MulticlusterRoleAssignment")
					time.Sleep(2 * time.Second)

					By("waiting for MulticlusterRoleAssignment to be created and fetching it")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple1Name, openClusterManagementGlobalSetNamespace)

					By("unmarshaling MulticlusterRoleAssignment json")
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch ClusterPermissions from all managed clusters", func() {
					clusterPermissions := []*clusterpermissionv1alpha1.ClusterPermission{
						&clusterPermission01, &clusterPermission02, &clusterPermission03}

					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf(
							"waiting for ClusterPermission to be created and fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON("clusterpermissions",
							"mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], clusterPermissions[i-1])
					}
				})
			})

			Context("ClusterPermission validation", func() {
				It("should have correct content for managedcluster01", func() {
					By("verifying ClusterPermission content in managedcluster01 namespace")
					Expect(clusterPermission01.Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermission01.Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermission01.Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermission01.Spec.RoleBindings).To(HaveLen(4))

					expectedBindings := []ExpectedBinding{
						{RoleName: "admin", Namespace: ""},
						{RoleName: "view", Namespace: "default"},
						{RoleName: "view", Namespace: "kube-system"},
						{RoleName: "system:monitoring", Namespace: "monitoring"},
						{RoleName: "system:monitoring", Namespace: "observability"},
					}
					validateClusterPermissionBindings(clusterPermission01, "test-user-multiple-1", expectedBindings)
				})

				It("should have correct content for managedcluster02", func() {
					By("verifying ClusterPermission content in managedcluster02 namespace")
					Expect(clusterPermission02.Spec.ClusterRoleBindings).To(BeNil())
					Expect(clusterPermission02.Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermission02.Spec.RoleBindings).To(HaveLen(4))

					expectedBindings := []ExpectedBinding{
						{RoleName: "view", Namespace: "default"},
						{RoleName: "view", Namespace: "kube-system"},
						{RoleName: "system:monitoring", Namespace: "monitoring"},
						{RoleName: "system:monitoring", Namespace: "observability"},
					}
					validateClusterPermissionBindings(clusterPermission02, "test-user-multiple-1", expectedBindings)
				})

				It("should have correct content for managedcluster03", func() {
					By("verifying ClusterPermission content in managedcluster03 namespace")
					Expect(clusterPermission03.Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermission03.Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermission03.Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermission03.Spec.RoleBindings).To(HaveLen(2))

					expectedBindings := []ExpectedBinding{
						{RoleName: "edit", Namespace: ""},
						{RoleName: "system:monitoring", Namespace: "monitoring"},
						{RoleName: "system:monitoring", Namespace: "observability"},
					}
					validateClusterPermissionBindings(clusterPermission03, "test-user-multiple-1", expectedBindings)
				})
			})

			Context("MulticlusterRoleAssignment status validation", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment statuses", func() {
					By("verifying all role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(4))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName,
						"view-assignment-namespaced-clusters-1-2")
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "edit-assignment-cluster-3")
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "admin-assignment-cluster-1")
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName,
						"monitoring-assignment-namespaced-all-clusters")
				})
			})
		})
	})
})

// ExpectedBinding represents a role binding we expect to find in a ClusterPermission.
type ExpectedBinding struct {
	// RoleName is the name of the role
	RoleName string
	// Namespace is the namespace for the binding. If binding is cluster scoped, leave this as an empty string
	Namespace string
}

// validateClusterPermissionBindings validates that a ClusterPermission contains expected bindings with correct subject.
func validateClusterPermissionBindings(clusterPermission clusterpermissionv1alpha1.ClusterPermission,
	expectedSubjectName string, expectedBindings []ExpectedBinding) {

	if clusterPermission.Spec.RoleBindings != nil {
		for _, binding := range *clusterPermission.Spec.RoleBindings {
			Expect(binding.Subjects).To(HaveLen(1))
			Expect(binding.Subjects[0].Name).To(Equal(expectedSubjectName))
		}
	}

	if clusterPermission.Spec.ClusterRoleBindings != nil {
		for _, binding := range *clusterPermission.Spec.ClusterRoleBindings {
			Expect(binding.Subjects).To(HaveLen(1))
			Expect(binding.Subjects[0].Name).To(Equal(expectedSubjectName))
		}
	}

	for _, expected := range expectedBindings {
		found := false

		if expected.Namespace == "" {
			if clusterPermission.Spec.ClusterRoleBindings != nil {
				for _, binding := range *clusterPermission.Spec.ClusterRoleBindings {
					if binding.RoleRef.Name == expected.RoleName {
						found = true
						break
					}
				}
			}
		} else {
			if clusterPermission.Spec.RoleBindings != nil {
				for _, binding := range *clusterPermission.Spec.RoleBindings {
					if binding.RoleRef.Name == expected.RoleName && binding.Namespace == expected.Namespace {
						found = true
						break
					}
				}
			}
		}

		Expect(found).To(BeTrue(), fmt.Sprintf("Expected binding with role %s and namespace %s not found",
			expected.RoleName, expected.Namespace))
	}
}

// validateMRASuccessConditions validates the expected success conditions for a MulticlusterRoleAssignment.
func validateMRASuccessConditions(mra rbacv1alpha1.MulticlusterRoleAssignment) {
	readyCondition := findCondition(mra.Status.Conditions, "Ready")
	Expect(readyCondition).NotTo(BeNil())
	Expect(readyCondition.Status).To(Equal(metav1.ConditionTrue))
	Expect(readyCondition.Reason).To(Equal("AllApplied"))
	Expect(readyCondition.Message).To(ContainSubstring("role assignments applied successfully"))

	appliedCondition := findCondition(mra.Status.Conditions, "Applied")
	Expect(appliedCondition).NotTo(BeNil())
	Expect(appliedCondition.Status).To(Equal(metav1.ConditionTrue))
	Expect(appliedCondition.Reason).To(Equal("ClusterPermissionApplied"))
	Expect(appliedCondition.Message).To(Equal("ClusterPermission applied successfully"))

	validatedCondition := findCondition(mra.Status.Conditions, "Validated")
	Expect(validatedCondition).NotTo(BeNil())
	Expect(validatedCondition.Status).To(Equal(metav1.ConditionTrue))
	Expect(validatedCondition.Reason).To(Equal("SpecIsValid"))
	Expect(validatedCondition.Message).To(Equal("Spec validation passed"))
}

// findCondition finds a condition by type in a slice of conditions.
func findCondition(conditions []metav1.Condition, conditionType string) *metav1.Condition {
	for i := range conditions {
		if conditions[i].Type == conditionType {
			return &conditions[i]
		}
	}
	return nil
}

// mapRoleAssignmentsByName creates a map of role assignments indexed by name.
func mapRoleAssignmentsByName(
	mra rbacv1alpha1.MulticlusterRoleAssignment) map[string]rbacv1alpha1.RoleAssignmentStatus {

	roleAssignmentsByName := make(map[string]rbacv1alpha1.RoleAssignmentStatus)
	for _, ra := range mra.Status.RoleAssignments {
		roleAssignmentsByName[ra.Name] = ra
	}
	return roleAssignmentsByName
}

// validateRoleAssignmentSuccessStatus validates that a role assignment has the expected success statuses.
func validateRoleAssignmentSuccessStatus(roleAssignmentsByName map[string]rbacv1alpha1.RoleAssignmentStatus,
	name string) {

	assignment := roleAssignmentsByName[name]
	Expect(assignment.Name).To(Equal(name))
	Expect(assignment.Status).To(Equal("Active"))
	Expect(assignment.Reason).To(Equal("ClusterPermissionApplied"))
	Expect(assignment.Message).To(Equal("ClusterPermission applied successfully"))
}

// applyK8sManifest applies a Kubernetes manifest file using kubectl.
func applyK8sManifest(manifestPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", manifestPath)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

// fetchK8sResourceJSON waits for a Kubernetes resource to be available and returns its JSON representation
func fetchK8sResourceJSON(resourceType, resourceName, namespace string) string {
	var resourceJSON string
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", resourceType, resourceName, "-n", namespace, "-o", "json")
		var err error
		resourceJSON, err = utils.Run(cmd)
		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(resourceJSON).NotTo(BeEmpty())
	}, 2*time.Minute).Should(Succeed())
	return resourceJSON
}

// unmarshalJSON unmarshals JSON data into the provided target struct.
func unmarshalJSON(jsonData string, target any) {
	err := json.Unmarshal([]byte(jsonData), target)
	Expect(err).NotTo(HaveOccurred())
}

// cleanupTestResources cleans up MulticlusterRoleAssignment and ClusterPermissions for a test.
func cleanupTestResources(mraName string, clusterNames []string) {
	By(fmt.Sprintf("cleaning up MulticlusterRoleAssignment %s", mraName))
	cmd := exec.Command(
		"kubectl", "delete", "multiclusterroleassignment", mraName, "-n", openClusterManagementGlobalSetNamespace)
	_, _ = utils.Run(cmd)

	By("cleaning up ClusterPermissions")
	for _, clusterName := range clusterNames {
		cmd = exec.Command("kubectl", "delete", "clusterpermissions", "mra-managed-permissions", "-n", clusterName)
		_, _ = utils.Run(cmd)
	}
}

// serviceAccountToken returns a token for the specified service account in the given namespace.
// It uses the Kubernetes TokenRequest API to generate a token by directly sending a request
// and parsing the resulting token from the API response.
func serviceAccountToken() (string, error) {
	const tokenRequestRawString = `{
		"apiVersion": "authentication.k8s.io/v1",
		"kind": "TokenRequest"
	}`

	// Temporary file to store the token request
	secretName := fmt.Sprintf("%s-token-request", serviceAccountName)
	tokenRequestFile := filepath.Join("/tmp", secretName)
	err := os.WriteFile(tokenRequestFile, []byte(tokenRequestRawString), os.FileMode(0o644))
	if err != nil {
		return "", err
	}

	var out string
	verifyTokenCreation := func(g Gomega) {
		// Execute kubectl command to create the token
		cmd := exec.Command("kubectl", "create", "--raw", fmt.Sprintf(
			"/api/v1/namespaces/%s/serviceaccounts/%s/token",
			namespace,
			serviceAccountName,
		), "-f", tokenRequestFile)

		output, err := cmd.CombinedOutput()
		g.Expect(err).NotTo(HaveOccurred())

		// Parse the JSON output to extract the token
		var token tokenRequest
		err = json.Unmarshal(output, &token)
		g.Expect(err).NotTo(HaveOccurred())

		out = token.Status.Token
	}
	Eventually(verifyTokenCreation).Should(Succeed())

	return out, err
}

// getMetricsOutput retrieves and returns the logs from the curl pod used to access the metrics endpoint.
func getMetricsOutput() string {
	By("getting the curl-metrics logs")
	cmd := exec.Command("kubectl", "logs", "curl-metrics", "-n", namespace)
	metricsOutput, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred(), "Failed to retrieve logs from curl pod")
	Expect(metricsOutput).To(ContainSubstring("< HTTP/1.1 200 OK"))
	return metricsOutput
}

// tokenRequest is a simplified representation of the Kubernetes TokenRequest API response,
// containing only the token field that we need to extract.
type tokenRequest struct {
	Status struct {
		Token string `json:"token"`
	} `json:"status"`
}
