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

// clusterPermissionOwnerAnnotationPrefix is the owner binding annotation for ClusterPermission binding ownership
// tracking
const clusterPermissionOwnerAnnotationPrefix = "owner.rbac.open-cluster-management.io/"

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
		// the "allows-errors" label: It("should handle invalid input",  func() { ... }). Since
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
						// ClusterRoleBinding
						{RoleName: "view", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermission, expectedBindings)
				})

				It("should have correct owner annotations", func() {
					By("verifying ClusterPermission has correct owner annotations for this MRA")
					validateMRAOwnerAnnotations(clusterPermission, mra)

					By("verifying binding annotations have semantic consistency")
					validateBindingConsistency(clusterPermission, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
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

		// !!!IMPORTANT!!!
		// This context reuses Kubernetes resources created from the previous context. Keep this in mind when
		// running/debugging these tests - they depend on the previous context having run successfully.
		Context("should modify ClusterPermission when MulticlusterRoleAssignment role name is edited", func() {
			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("resource modification and fetching", func() {
				var clusterPermissionJSON, mraJSON string

				It("should modify and fetch MulticlusterRoleAssignment", func() {
					By("modifying the MRA to change cluster role from 'view' to 'edit'")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleCRBName, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)

					mra.Spec.RoleAssignments[0].ClusterRole = "edit"
					patchK8sMRA(&mra)

					By("waiting for controller to process the updated MulticlusterRoleAssignment")
					time.Sleep(2 * time.Second)

					By("waiting for updated MulticlusterRoleAssignment to be fetched")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleCRBName, openClusterManagementGlobalSetNamespace)

					By("unmarshaling updated MulticlusterRoleAssignment json")
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch updated ClusterPermission", func() {
					By("waiting for updated ClusterPermission to be fetched")
					clusterPermissionJSON = fetchK8sResourceJSON(
						"clusterpermissions", "mra-managed-permissions", "managedcluster01")

					By("unmarshaling updated ClusterPermission json")
					unmarshalJSON(clusterPermissionJSON, &clusterPermission)
				})
			})

			Context("ClusterPermission validation", func() {
				It("should have correct ClusterRoleBinding", func() {
					By("verifying ClusterPermission has correct ClusterRoleBinding")
					Expect(*clusterPermission.Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermission.Spec.RoleBindings).To(BeNil())

					expectedBindings := []ExpectedBinding{
						{RoleName: "edit", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermission, expectedBindings)
				})

				It("should have correct owner annotations", func() {
					By("verifying ClusterPermission has correct owner annotations for this MRA")
					validateMRAOwnerAnnotations(clusterPermission, mra)

					By("verifying binding annotations have semantic consistency")
					validateBindingConsistency(clusterPermission, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
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
						// RoleBindings
						{RoleName: "edit", Namespace: "default", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "kube-system", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "monitoring", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "observability", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "logging", SubjectName: "test-user-single-rolebinding"},
					}
					validateClusterPermissionBindings(clusterPermission, expectedBindings)
				})

				It("should have correct owner annotations", func() {
					By("verifying ClusterPermission has correct owner annotations for this MRA")
					validateMRAOwnerAnnotations(clusterPermission, mra)

					By("verifying binding annotations have semantic consistency")
					validateBindingConsistency(clusterPermission, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
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
			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
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
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf(
							"waiting for ClusterPermission to be created and fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON("clusterpermissions",
							"mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])
					}
				})
			})

			Context("ClusterPermission validation", func() {
				It("should have correct content for managedcluster01", func() {
					By("verifying ClusterPermission content in managedcluster01 namespace")
					Expect(clusterPermissions[0].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[0].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.RoleBindings).To(HaveLen(4))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBinding
						{RoleName: "admin", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[0], expectedBindings)
				})

				It("should have correct content for managedcluster02", func() {
					By("verifying ClusterPermission content in managedcluster02 namespace")
					Expect(clusterPermissions[1].Spec.ClusterRoleBindings).To(BeNil())
					Expect(clusterPermissions[1].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.RoleBindings).To(HaveLen(4))

					expectedBindings := []ExpectedBinding{
						// RoleBindings
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[1], expectedBindings)
				})

				It("should have correct content for managedcluster03", func() {
					By("verifying ClusterPermission content in managedcluster03 namespace")
					Expect(clusterPermissions[2].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[2].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.RoleBindings).To(HaveLen(2))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBinding
						{RoleName: "edit", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[2], expectedBindings)
				})

				It("should have correct owner annotations for all clusters", func() {
					By("verifying ClusterPermission owner annotations for all clusters")
					for _, cp := range clusterPermissions {
						validateMRAOwnerAnnotations(cp, mra)
					}

					By("verifying binding annotations have semantic consistency")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
					}
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

		Context("should create multiple MulticlusterRoleAssignments and ClusterPermissions - tests MRA create and "+
			"ClusterPermissions modify", func() {

			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
			var mras [4]rbacv1alpha1.MulticlusterRoleAssignment

			Context("resource creation and fetching", func() {
				var mraJSONs [4]string
				var clusterPermissionJSONs [3]string

				It("should create and fetch all MulticlusterRoleAssignments in sequence", func() {
					By("creating all MulticlusterRoleAssignments sequentially to test CREATE and MODIFY operations")
					manifestFiles := []string{
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_1.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml",
					}
					for _, manifestFile := range manifestFiles {
						applyK8sManifest(manifestFile)
					}

					By("waiting for controller to process the MulticlusterRoleAssignment")
					time.Sleep(4 * time.Second)

					By("fetching all four MulticlusterRoleAssignments")
					mraNames := []string{
						testMulticlusterRoleAssignmentMultiple2Name,
						testMulticlusterRoleAssignmentMultiple1Name,
						testMulticlusterRoleAssignmentSingleRBName,
						testMulticlusterRoleAssignmentSingleCRBName,
					}
					for i, mraName := range mraNames {
						mraJSONs[i] = fetchK8sResourceJSON(
							"multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
					}

					By("unmarshaling all MulticlusterRoleAssignment JSONs")
					for i := range mras {
						unmarshalJSON(mraJSONs[i], &mras[i])
					}
				})

				It("should fetch merged ClusterPermissions for all managed clusters", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf(
							"waiting for merged ClusterPermission to be ready and fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON("clusterpermissions",
							"mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])
					}
				})
			})

			Context("ClusterPermission merged content validation", func() {
				It("should have correctly merged content for managedcluster01", func() {
					By("verifying merged ClusterPermission content in managedcluster01 namespace")
					Expect(clusterPermissions[0].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.ClusterRoleBindings).To(HaveLen(4))
					Expect(clusterPermissions[0].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.RoleBindings).To(HaveLen(7))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "admin", Namespace: "", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "", SubjectName: "test-user-multiple-2"},
						{RoleName: "admin", Namespace: "", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
						// RoleBindings
						{RoleName: "edit", Namespace: "development", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[0], expectedBindings)
				})

				It("should have correctly merged content for managedcluster02", func() {
					By("verifying merged ClusterPermission content in managedcluster02 namespace")
					Expect(clusterPermissions[1].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[1].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.RoleBindings).To(HaveLen(13))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "test-user-multiple-2"},
						// RoleBindings
						{RoleName: "edit", Namespace: "default", SubjectName: "test-user-multiple-2"},
						{RoleName: "edit", Namespace: "development", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
						{RoleName: "edit", Namespace: "default", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "kube-system", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "monitoring", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "observability", SubjectName: "test-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "logging", SubjectName: "test-user-single-rolebinding"},
					}
					validateClusterPermissionBindings(clusterPermissions[1], expectedBindings)
				})

				It("should have correctly merged content for managedcluster03", func() {
					By("verifying merged ClusterPermission content in managedcluster03 namespace")
					Expect(clusterPermissions[2].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.ClusterRoleBindings).To(HaveLen(2))
					Expect(clusterPermissions[2].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.RoleBindings).To(HaveLen(6))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "test-user-multiple-2"},
						{RoleName: "edit", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-2"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "test-user-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-2"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[2], expectedBindings)
				})

				It("should have correct owner annotations for all clusters", func() {
					By("verifying ClusterPermission owner annotations for all clusters")
					for _, cp := range clusterPermissions {
						for _, mra := range mras {
							validateMRAOwnerAnnotations(cp, mra)
						}
					}

					By("verifying binding annotations have semantic consistency")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, mras[:])
					}
				})
			})

			//nolint:dupl
			Context("MulticlusterRoleAssignment status validation", func() {
				It("should have correct conditions for all MRAs", func() {
					By("verifying MulticlusterRoleAssignment conditions for all MRAs")
					for _, mra := range mras {
						validateMRASuccessConditions(mra)
					}
				})

				It("should have correct role assignment statuses for all MRAs", func() {
					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentMultiple2Name))
					Expect(mras[0].Status.RoleAssignments).To(HaveLen(6))
					roleAssignmentsByName1 := mapRoleAssignmentsByName(mras[0])
					assignmentNames1 := []string{
						"admin-assignment-cluster-1",
						"view-assignment-all-clusters",
						"edit-assignment-single-namespace",
						"monitoring-assignment-multi-namespace-single-cluster",
						"dev-assignment-single-namespace-multi-cluster",
						"logging-assignment-multi-namespace-multi-cluster",
					}
					for _, name := range assignmentNames1 {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName1, name)
					}

					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentMultiple1Name))
					Expect(mras[1].Status.RoleAssignments).To(HaveLen(4))
					roleAssignmentsByName2 := mapRoleAssignmentsByName(mras[1])
					assignmentNames2 := []string{
						"view-assignment-namespaced-clusters-1-2",
						"edit-assignment-cluster-3",
						"admin-assignment-cluster-1",
						"monitoring-assignment-namespaced-all-clusters",
					}
					for _, name := range assignmentNames2 {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName2, name)
					}

					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentSingleRBName))
					Expect(mras[2].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName3 := mapRoleAssignmentsByName(mras[2])
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName3, "test-role-assignment-namespaced")

					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentSingleCRBName))
					Expect(mras[3].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName4 := mapRoleAssignmentsByName(mras[3])
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName4, "test-role-assignment")
				})
			})
		})

		// !!!IMPORTANT!!!
		// This context reuses Kubernetes resources created from the previous context. Keep this in mind when
		// running/debugging these tests - they depend on the previous context having run successfully.
		Context("should modify multiple MulticlusterRoleAssignments with comprehensive changes and update "+
			"ClusterPermissions accordingly", func() {

			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
			var mras [4]rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple2Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple1Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
				cleanupTestResources(testMulticlusterRoleAssignmentSingleRBName, []string{"managedcluster02"})
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("resource modification and fetching", func() {
				var mraJSONs [4]string
				var clusterPermissionJSONs [3]string
				const groupSubjectKind = "Group"

				It("should modify and fetch all MulticlusterRoleAssignments with comprehensive changes", func() {
					By("fetching existing MulticlusterRoleAssignments to modify them")
					mraNames := []string{
						testMulticlusterRoleAssignmentMultiple2Name,
						testMulticlusterRoleAssignmentMultiple1Name,
						testMulticlusterRoleAssignmentSingleRBName,
						testMulticlusterRoleAssignmentSingleCRBName,
					}
					for i, mraName := range mraNames {
						mraJSONs[i] = fetchK8sResourceJSON(
							"multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
						unmarshalJSON(mraJSONs[i], &mras[i])
					}

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentMultiple2Name))
					mras[0].Spec.Subject.Name = "modified-group-multiple-2"
					mras[0].Spec.Subject.Kind = groupSubjectKind
					mras[0].Spec.RoleAssignments[0].Name = "modified-admin-assignment-cluster-1"
					mras[0].Spec.RoleAssignments[0].ClusterRole = "edit"
					mras[0].Spec.RoleAssignments[1].ClusterSelection.ClusterNames = append(
						mras[0].Spec.RoleAssignments[1].ClusterSelection.ClusterNames, "managedcluster01")
					mras[0].Spec.RoleAssignments[2].TargetNamespaces = append(
						mras[0].Spec.RoleAssignments[2].TargetNamespaces, "new-dev-ns")
					patchK8sMRA(&mras[0])

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentMultiple1Name))
					mras[1].Spec.Subject.Kind = groupSubjectKind
					mras[1].Spec.RoleAssignments[0].Name = "modified-view-assignment-namespaced-clusters-1-2"
					mras[1].Spec.RoleAssignments[0].ClusterRole = "admin"
					mras[1].Spec.RoleAssignments[1].Name = "modified-edit-assignment-cluster-3"
					mras[1].Spec.RoleAssignments[1].ClusterRole = "cluster-admin"
					mras[1].Spec.RoleAssignments[2].Name = "modified-admin-assignment-cluster-1"
					mras[1].Spec.RoleAssignments[3].TargetNamespaces = append(
						mras[1].Spec.RoleAssignments[3].TargetNamespaces, "metrics")
					patchK8sMRA(&mras[1])

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentSingleRBName))
					mras[2].Spec.Subject.Name = "modified-user-single-rolebinding"
					mras[2].Spec.RoleAssignments[0].Name = "modified-test-role-assignment-namespaced"
					mras[2].Spec.RoleAssignments[0].ClusterSelection.ClusterNames = append(
						mras[2].Spec.RoleAssignments[0].ClusterSelection.ClusterNames, "managedcluster01",
						"managedcluster03")
					mras[2].Spec.RoleAssignments[0].TargetNamespaces = append(
						mras[2].Spec.RoleAssignments[0].TargetNamespaces, "staging", "prod")
					patchK8sMRA(&mras[2])

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentSingleCRBName))
					mras[3].Spec.Subject.Name = "modified-group-single-clusterrolebinding"
					mras[3].Spec.Subject.Kind = groupSubjectKind
					mras[3].Spec.RoleAssignments[0].Name = "modified-test-role-assignment"
					mras[3].Spec.RoleAssignments[0].ClusterRole = "admin"
					mras[3].Spec.RoleAssignments[0].TargetNamespaces = []string{"default", "kube-system",
						"applications"}
					mras[3].Spec.RoleAssignments[0].ClusterSelection.ClusterNames = append(
						mras[3].Spec.RoleAssignments[0].ClusterSelection.ClusterNames, "managedcluster02",
						"managedcluster03")
					patchK8sMRA(&mras[3])

					By("waiting for controller to process all comprehensively updated MulticlusterRoleAssignments")
					time.Sleep(4 * time.Second)

					By("fetching all comprehensively updated MulticlusterRoleAssignments")
					for i, mraName := range mraNames {
						mraJSONs[i] = fetchK8sResourceJSON(
							"multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
						unmarshalJSON(mraJSONs[i], &mras[i])
					}
				})

				It("should fetch updated merged ClusterPermissions for all managed clusters", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf("waiting for comprehensively updated merged ClusterPermission to be ready and "+
							"fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON(
							"clusterpermissions", "mra-managed-permissions", clusterName)

						By(fmt.Sprintf(
							"unmarshaling comprehensively updated ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])
					}
				})
			})

			//nolint:dupl
			Context("ClusterPermission merged content validation after comprehensive modifications", func() {
				It("should have correctly updated content for managedcluster01 with comprehensive changes", func() {
					By("verifying comprehensively updated ClusterPermission content in managedcluster01 namespace")
					Expect(clusterPermissions[0].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.ClusterRoleBindings).To(HaveLen(3))
					Expect(clusterPermissions[0].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.RoleBindings).To(HaveLen(18))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "edit", Namespace: "", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "", SubjectName: "modified-group-multiple-2"},
						{RoleName: "admin", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "edit", Namespace: "development", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "modified-group-multiple-2"},
						{RoleName: "admin", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "admin", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "metrics", SubjectName: "test-user-multiple-1"},
						{RoleName: "edit", Namespace: "default", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "kube-system", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "monitoring", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "observability", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "logging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "staging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "prod", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "admin", Namespace: "default",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications",
							SubjectName: "modified-group-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermissions[0], expectedBindings)
				})

				It("should have correctly updated content for managedcluster02 with comprehensive changes", func() {
					By("verifying comprehensively updated ClusterPermission content in managedcluster02 namespace")
					Expect(clusterPermissions[1].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[1].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.RoleBindings).To(HaveLen(20))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "modified-group-multiple-2"},
						// RoleBindings
						{RoleName: "edit", Namespace: "default", SubjectName: "modified-group-multiple-2"},
						{RoleName: "edit", Namespace: "new-dev-ns", SubjectName: "modified-group-multiple-2"},
						{RoleName: "edit", Namespace: "development", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "modified-group-multiple-2"},
						{RoleName: "admin", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "admin", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "metrics", SubjectName: "test-user-multiple-1"},
						{RoleName: "edit", Namespace: "default", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "kube-system", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "monitoring", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "observability", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "logging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "staging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "prod", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "admin", Namespace: "default",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications",
							SubjectName: "modified-group-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermissions[1], expectedBindings)
				})

				It("should have correctly updated content for managedcluster03 with comprehensive changes", func() {
					By("verifying comprehensively updated ClusterPermission content in managedcluster03 namespace")
					Expect(clusterPermissions[2].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.ClusterRoleBindings).To(HaveLen(2))
					Expect(clusterPermissions[2].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.RoleBindings).To(HaveLen(17))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "modified-group-multiple-2"},
						{RoleName: "cluster-admin", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "modified-group-multiple-2"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "logging", SubjectName: "modified-group-multiple-2"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "modified-group-multiple-2"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "metrics", SubjectName: "test-user-multiple-1"},
						{RoleName: "edit", Namespace: "default", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "kube-system", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "monitoring", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "observability", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "logging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "staging", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "edit", Namespace: "prod", SubjectName: "modified-user-single-rolebinding"},
						{RoleName: "admin", Namespace: "default",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system",
							SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications",
							SubjectName: "modified-group-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermissions[2], expectedBindings)
				})

				It("should have correct owner annotations for all clusters after comprehensive modifications", func() {
					By("verifying ClusterPermission owner annotations for all clusters after comprehensive changes")
					for _, cp := range clusterPermissions {
						for _, mra := range mras {
							validateMRAOwnerAnnotations(cp, mra)
						}
					}

					By("verifying binding annotations have semantic consistency after comprehensive modifications")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, mras[:])
					}
				})
			})

			//nolint:dupl
			Context("MulticlusterRoleAssignment status validation after comprehensive modifications", func() {
				It("should have correct conditions for all comprehensively modified MRAs", func() {
					By("verifying MulticlusterRoleAssignment conditions for all comprehensively modified MRAs")
					for _, mra := range mras {
						validateMRASuccessConditions(mra)
					}
				})

				It("should have correct role assignment statuses for all comprehensively modified MRAs", func() {
					By(fmt.Sprintf("verifying role assignment status details for comprehensively modified %s",
						testMulticlusterRoleAssignmentMultiple2Name))

					Expect(mras[0].Status.RoleAssignments).To(HaveLen(6))
					roleAssignmentsByName1 := mapRoleAssignmentsByName(mras[0])
					assignmentNames1 := []string{
						"modified-admin-assignment-cluster-1",
						"view-assignment-all-clusters",
						"edit-assignment-single-namespace",
						"monitoring-assignment-multi-namespace-single-cluster",
						"dev-assignment-single-namespace-multi-cluster",
						"logging-assignment-multi-namespace-multi-cluster",
					}
					for _, name := range assignmentNames1 {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName1, name)
					}

					By(fmt.Sprintf("verifying role assignment status details for comprehensively modified %s",
						testMulticlusterRoleAssignmentMultiple1Name))

					Expect(mras[1].Status.RoleAssignments).To(HaveLen(4))
					roleAssignmentsByName2 := mapRoleAssignmentsByName(mras[1])
					assignmentNames2 := []string{
						"modified-view-assignment-namespaced-clusters-1-2",
						"modified-edit-assignment-cluster-3",
						"modified-admin-assignment-cluster-1",
						"monitoring-assignment-namespaced-all-clusters",
					}
					for _, name := range assignmentNames2 {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName2, name)
					}

					By(fmt.Sprintf("verifying role assignment status details for comprehensively modified %s",
						testMulticlusterRoleAssignmentSingleRBName))

					Expect(mras[2].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName3 := mapRoleAssignmentsByName(mras[2])
					validateRoleAssignmentSuccessStatus(
						roleAssignmentsByName3, "modified-test-role-assignment-namespaced")

					By(fmt.Sprintf("verifying role assignment status details for comprehensively modified %s",
						testMulticlusterRoleAssignmentSingleCRBName))

					Expect(mras[3].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName4 := mapRoleAssignmentsByName(mras[3])
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName4, "modified-test-role-assignment")
				})
			})
		})
	})
})

// ExpectedBinding represents a role binding that we expect to find in a ClusterPermission.
type ExpectedBinding struct {
	// RoleName is the name of the role
	RoleName string
	// Namespace is the namespace for the binding. If binding is cluster scoped, leave this as an empty string
	Namespace string
	// SubjectName is the expected subject name for this binding
	SubjectName string
}

// validateClusterPermissionBindings validates that a ClusterPermission contains expected bindings.
func validateClusterPermissionBindings(clusterPermission clusterpermissionv1alpha1.ClusterPermission,
	expectedBindings []ExpectedBinding) {

	for _, expected := range expectedBindings {
		found := false

		if expected.Namespace == "" {
			if clusterPermission.Spec.ClusterRoleBindings != nil {
				for _, binding := range *clusterPermission.Spec.ClusterRoleBindings {
					if binding.RoleRef.Name == expected.RoleName &&
						len(binding.Subjects) == 1 &&
						binding.Subjects[0].Name == expected.SubjectName {
						found = true
						break
					}
				}
			}
		} else {
			if clusterPermission.Spec.RoleBindings != nil {
				for _, binding := range *clusterPermission.Spec.RoleBindings {
					if binding.RoleRef.Name == expected.RoleName &&
						binding.Namespace == expected.Namespace &&
						len(binding.Subjects) == 1 &&
						binding.Subjects[0].Name == expected.SubjectName {
						found = true
						break
					}
				}
			}
		}

		Expect(found).To(BeTrue(), fmt.Sprintf("Expected binding with role %s, namespace %s, and subject %s not found",
			expected.RoleName, expected.Namespace, expected.SubjectName))
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

// patchK8sMRA applies a patch to a MulticlusterRoleAssignment using kubectl patch.
func patchK8sMRA(mra *rbacv1alpha1.MulticlusterRoleAssignment) {
	patchSpec := map[string]any{
		"spec": mra.Spec,
	}
	patchBytes, err := json.Marshal(patchSpec)
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command("kubectl", "patch", "multiclusterroleassignment", openClusterManagementGlobalSetNamespace, "-n",
		namespace, "--type", "merge", "-p", string(patchBytes))
	_, err = utils.Run(cmd)
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

// validateMRAOwnerAnnotations validates that this ClusterPermission contains the correct number of owner annotations
// for this MulticlusterRoleAssignment, with proper MRA identifier values, and no unexpected annotations.
func validateMRAOwnerAnnotations(cp clusterpermissionv1alpha1.ClusterPermission,
	mra rbacv1alpha1.MulticlusterRoleAssignment) {

	mraNamespaceAndName := fmt.Sprintf("%s/%s", mra.Namespace, mra.Name)
	clusterName := cp.Namespace

	expectedAnnotationCount := 0
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if !slices.Contains(roleAssignment.ClusterSelection.ClusterNames, clusterName) {
			continue
		}

		if len(roleAssignment.TargetNamespaces) == 0 {
			expectedAnnotationCount++
		} else {
			expectedAnnotationCount += len(roleAssignment.TargetNamespaces)
		}
	}

	actualAnnotationCount := 0
	if cp.Annotations != nil {
		for annotationKey, annotationValue := range cp.Annotations {
			if strings.HasPrefix(annotationKey, clusterPermissionOwnerAnnotationPrefix) &&
				annotationValue == mraNamespaceAndName {
				actualAnnotationCount++
			}
		}
	}

	Expect(actualAnnotationCount).To(Equal(expectedAnnotationCount),
		fmt.Sprintf("Expected %d owner annotations for MRA %s on ClusterPermission %s/%s, but found %d",
			expectedAnnotationCount, mraNamespaceAndName, cp.Namespace, cp.Name, actualAnnotationCount))
}

// validateBindingConsistency validates that each owner annotation references a ClusterPermission binding whose
// properties (subject, role, namespace) are consistent with what exists on the referenced MRA.
func validateBindingConsistency(cp clusterpermissionv1alpha1.ClusterPermission,
	mras []rbacv1alpha1.MulticlusterRoleAssignment) {

	for annotationKey, annotationValue := range cp.Annotations {
		if !strings.HasPrefix(annotationKey, clusterPermissionOwnerAnnotationPrefix) {
			continue
		}
		referencedMRANamespaceAndName := annotationValue

		bindingName := strings.TrimPrefix(annotationKey, clusterPermissionOwnerAnnotationPrefix)

		var referencedMRA *rbacv1alpha1.MulticlusterRoleAssignment
		for _, mra := range mras {
			if fmt.Sprintf("%s/%s", mra.Namespace, mra.Name) == referencedMRANamespaceAndName {
				referencedMRA = &mra
				break
			}
		}
		Expect(referencedMRA).NotTo(BeNil(),
			fmt.Sprintf("MRA %s referenced in ClusterPermission %s/%s annotation not found",
				referencedMRANamespaceAndName, cp.Namespace, cp.Name))

		binding := locateClusterPermissionBinding(cp, bindingName)
		Expect(binding).NotTo(BeNil(),
			fmt.Sprintf("Binding %s referenced in annotation not found in ClusterPermission %s/%s", bindingName,
				cp.Namespace, cp.Name))

		exists := checkMRAForBindingExistance(*referencedMRA, *binding, cp.Namespace)
		Expect(exists).To(BeTrue(),
			fmt.Sprintf("MRA %s does not contain binding %s in ClusterPermission %s/%s", referencedMRANamespaceAndName,
				bindingName, cp.Namespace, cp.Name))
	}
}

// locateClusterPermissionBinding locates a binding by name in the ClusterPermission and extracts its properties.
func locateClusterPermissionBinding(cp clusterpermissionv1alpha1.ClusterPermission,
	bindingName string) *ExpectedBinding {

	if cp.Spec.ClusterRoleBindings != nil {
		for _, binding := range *cp.Spec.ClusterRoleBindings {
			if binding.Name == bindingName {
				Expect(binding.Subjects).To(HaveLen(1), "Expected exactly one subject in binding")
				return &ExpectedBinding{
					RoleName:    binding.RoleRef.Name,
					Namespace:   "",
					SubjectName: binding.Subjects[0].Name,
				}
			}
		}
	}

	if cp.Spec.RoleBindings != nil {
		for _, binding := range *cp.Spec.RoleBindings {
			if binding.Name == bindingName {
				Expect(binding.Subjects).To(HaveLen(1), "Expected exactly one subject in binding")
				return &ExpectedBinding{
					RoleName:    binding.RoleRef.Name,
					Namespace:   binding.Namespace,
					SubjectName: binding.Subjects[0].Name,
				}
			}
		}
	}

	return nil
}

// checkMRAForBindingExistance checks if the given MRA has a role assignment that would justify creating a binding with
// the given properties on the specified cluster.
func checkMRAForBindingExistance(mra rbacv1alpha1.MulticlusterRoleAssignment, binding ExpectedBinding,
	clusterName string) bool {

	if mra.Spec.Subject.Name != binding.SubjectName {
		return false
	}

	for _, roleAssignment := range mra.Spec.RoleAssignments {
		if !slices.Contains(roleAssignment.ClusterSelection.ClusterNames, clusterName) {
			continue
		}

		if roleAssignment.ClusterRole != binding.RoleName {
			continue
		}

		if binding.Namespace == "" {
			if len(roleAssignment.TargetNamespaces) == 0 {
				return true
			}
		} else {
			if slices.Contains(roleAssignment.TargetNamespaces, binding.Namespace) {
				return true
			}
		}
	}

	return false
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
