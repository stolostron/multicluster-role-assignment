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
	rbacv1 "k8s.io/api/rbac/v1"
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
		specReport := CurrentSpecReport()
		if specReport.Failed() {
			By("Skipping suite cleanup due to test failure - preserving cluster state for debugging")
			By("Controller logs, CRDs, and namespaces preserved for investigation")
			return
		}

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

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("resource creation and fetching", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create and fetch MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with one RoleAssignment")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml")

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

			Context("MulticlusterRoleAssignment validation", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment status", func() {
					By("verifying role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(2))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "test-role-assignment")
				})

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation matches targeted clusters")
					validateMRAAllClustersAnnotation(mra)
				})
			})
		})

		Context("should modify ClusterPermission when MulticlusterRoleAssignment role name is edited", func() {
			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("resource creation and modification", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create and modify MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with one RoleAssignment")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml")

					By("fetching the initial MulticlusterRoleAssignment")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleCRBName, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)

					By("modifying the MRA to change cluster role from 'view' to 'admin-role'")
					mra.Spec.RoleAssignments[0].ClusterRole = "admin-role"
					patchK8sResource(
						"multiclusterroleassignment", mra.Name, openClusterManagementGlobalSetNamespace, mra.Spec)

					By("fetching the updated MulticlusterRoleAssignment")
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
						{RoleName: "admin-role", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
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

			Context("MulticlusterRoleAssignment validation", func() {
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

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation matches targeted clusters")
					validateMRAAllClustersAnnotation(mra)
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

			Context("MulticlusterRoleAssignment validation", func() {
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

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation matches targeted clusters")
					validateMRAAllClustersAnnotation(mra)
				})
			})
		})

		Context("should delete ClusterPermission when MulticlusterRoleAssignment is deleted", func() {
			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleRBName, []string{"managedcluster02"})
			})

			It("should create and delete MulticlusterRoleAssignment", func() {
				By("creating a MulticlusterRoleAssignment with one namespaced RoleAssignment")
				applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_2.yaml")

				By("deleting the MulticlusterRoleAssignment")
				deleteK8sMRA(testMulticlusterRoleAssignmentSingleRBName)
			})

			It("should verify ClusterPermission is deleted", func() {
				By("verifying ClusterPermission is deleted")
				verifyK8sResourceDeleted("clusterpermissions", "mra-managed-permissions", "managedcluster02")
			})

			It("should verify MulticlusterRoleAssignment no longer exists", func() {
				By("verifying MulticlusterRoleAssignment is deleted")
				verifyK8sResourceDeleted("multiclusterroleassignment", testMulticlusterRoleAssignmentSingleRBName,
					openClusterManagementGlobalSetNamespace)
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

			Context("MulticlusterRoleAssignment validation", func() {
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

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation matches targeted clusters")
					validateMRAAllClustersAnnotation(mra)
				})
			})
		})

		Context("should handle creating and deleting a ClusterPermission for a new and unique cluster", func() {
			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple1Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03", "newmanagedcluster04"})

				By("cleaning up newmanagedcluster04 namespace and ManagedCluster")
				cmd := exec.Command("kubectl", "delete", "ns", "newmanagedcluster04")
				_, _ = utils.Run(cmd)

				managedClusterFile := "/tmp/newmanagedcluster04.yaml"
				cmd = exec.Command("kubectl", "delete", "-f", managedClusterFile)
				_, _ = utils.Run(cmd)
			})

			Context("initial resource creation, cluster addition, and new cluster RoleAssignment addition", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create initial MRA and managed cluster", func() {
					By("creating a MulticlusterRoleAssignment with multiple RoleAssignments")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_1.yaml")

					By("creating newmanagedcluster04 namespace")
					cmd := exec.Command("kubectl", "create", "ns", "newmanagedcluster04")
					_, err := utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())

					By("creating ManagedCluster newmanagedcluster04")
					managedClusterTemplate, err := os.ReadFile("test/testdata/managedcluster-template.yaml")
					Expect(err).NotTo(HaveOccurred())

					managedCluster := strings.ReplaceAll(
						string(managedClusterTemplate), "CLUSTER_NAME_PLACEHOLDER", "newmanagedcluster04")
					managedClusterFile := "/tmp/newmanagedcluster04.yaml"
					err = os.WriteFile(managedClusterFile, []byte(managedCluster), os.FileMode(0o644))
					Expect(err).NotTo(HaveOccurred())

					cmd = exec.Command("kubectl", "apply", "-f", managedClusterFile)
					_, err = utils.Run(cmd)
					Expect(err).NotTo(HaveOccurred())

					By("fetching and modifying MRA to add newmanagedcluster04 RoleAssignment")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple1Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)

					newRoleAssignment := rbacv1alpha1.RoleAssignment{
						Name:        "cluster04-assignment",
						ClusterRole: "view",
						ClusterSelection: rbacv1alpha1.ClusterSelection{
							Type:         "clusterNames",
							ClusterNames: []string{"newmanagedcluster04"},
						},
						TargetNamespaces: []string{"default", "kube-system"},
					}
					mra.Spec.RoleAssignments = append(mra.Spec.RoleAssignments, newRoleAssignment)
					patchK8sResource(
						"multiclusterroleassignment", mra.Name, openClusterManagementGlobalSetNamespace, mra.Spec)

					By("fetching updated MulticlusterRoleAssignment")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple1Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch ClusterPermission for newmanagedcluster04", func() {
					By("waiting for ClusterPermission to be created and fetching it from newmanagedcluster04")
					clusterPermissionJSON = fetchK8sResourceJSON(
						"clusterpermissions", "mra-managed-permissions", "newmanagedcluster04")

					By("unmarshaling ClusterPermission json for newmanagedcluster04")
					unmarshalJSON(clusterPermissionJSON, &clusterPermission)
				})
			})

			Context("ClusterPermission validation for new cluster", func() {
				It("should have correct content for newmanagedcluster04", func() {
					By("verifying ClusterPermission content in newmanagedcluster04 namespace")
					Expect(clusterPermission.Spec.ClusterRoleBindings).To(BeNil())
					Expect(clusterPermission.Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermission.Spec.RoleBindings).To(HaveLen(2))

					expectedBindings := []ExpectedBinding{
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
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

			Context("MulticlusterRoleAssignment validation after cluster addition", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment status", func() {
					By("verifying role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(5))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName, "cluster04-assignment")
				})

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation matches targeted clusters including newmanagedcluster04")
					validateMRAAllClustersAnnotation(mra)
				})
			})

			Context("unique cluster RoleAssignment removal", func() {
				var updatedMraJSON string

				It("should remove newmanagedcluster04 RoleAssignment", func() {
					By("fetching current MRA to remove newmanagedcluster04 RoleAssignment")
					updatedMraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple1Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(updatedMraJSON, &mra)

					By("removing cluster04-assignment from MRA")
					var updatedRoleAssignments []rbacv1alpha1.RoleAssignment
					for _, ra := range mra.Spec.RoleAssignments {
						if ra.Name != "cluster04-assignment" {
							updatedRoleAssignments = append(updatedRoleAssignments, ra)
						}
					}
					mra.Spec.RoleAssignments = updatedRoleAssignments
					patchK8sResource(
						"multiclusterroleassignment", mra.Name, openClusterManagementGlobalSetNamespace, mra.Spec)

					By("fetching updated MulticlusterRoleAssignment")
					updatedMraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple1Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(updatedMraJSON, &mra)
				})

				It("should verify ClusterPermission is deleted for newmanagedcluster04", func() {
					By("verifying ClusterPermission is deleted from newmanagedcluster04")
					verifyK8sResourceDeleted("clusterpermissions", "mra-managed-permissions", "newmanagedcluster04")
				})
			})

			Context("MulticlusterRoleAssignment validation after role assignment removal", func() {
				It("should have correct conditions", func() {
					By("verifying MulticlusterRoleAssignment conditions")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment status", func() {
					By("verifying role assignment status details")
					Expect(mra.Status.RoleAssignments).To(HaveLen(4))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)
					validateRoleAssignmentSuccessStatus(
						roleAssignmentsByName, "view-assignment-namespaced-clusters-1-2")
					validateRoleAssignmentSuccessStatus(
						roleAssignmentsByName, "edit-assignment-cluster-3")
					validateRoleAssignmentSuccessStatus(
						roleAssignmentsByName, "admin-assignment-cluster-1")
					validateRoleAssignmentSuccessStatus(
						roleAssignmentsByName, "monitoring-assignment-namespaced-all-clusters")
				})

				It("should have correct all clusters annotation", func() {
					By("verifying all clusters annotation no longer includes newmanagedcluster04")
					validateMRAAllClustersAnnotation(mra)
				})
			})
		})

		Context("should create multiple MulticlusterRoleAssignments and ClusterPermissions - tests MRA create and "+
			"ClusterPermissions modify", func() {

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

			//nolint:dupl
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
			Context("MulticlusterRoleAssignment validation", func() {
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

				It("should have correct all clusters annotations for all MRAs", func() {
					By("verifying all clusters annotations match targeted clusters for all MRAs")
					for _, mra := range mras {
						validateMRAAllClustersAnnotation(mra)
					}
				})
			})
		})

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

			Context("resource creation and comprehensive modification", func() {
				var mraJSONs [4]string
				var clusterPermissionJSONs [3]string
				const groupSubjectKind = "Group"

				It("should create and comprehensively modify all MulticlusterRoleAssignments", func() {
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

					By("fetching all four MulticlusterRoleAssignments to modify them")
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
					patchK8sResource(
						"multiclusterroleassignment", mras[0].Name, openClusterManagementGlobalSetNamespace, mras[0].Spec)

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentMultiple1Name))
					mras[1].Spec.Subject.Kind = groupSubjectKind
					mras[1].Spec.RoleAssignments[0].Name = "modified-view-assignment-namespaced-clusters-1-2"
					mras[1].Spec.RoleAssignments[0].ClusterRole = "admin2"
					mras[1].Spec.RoleAssignments[1].Name = "modified-edit-assignment-cluster-3"
					mras[1].Spec.RoleAssignments[1].ClusterRole = "cluster-admin"
					mras[1].Spec.RoleAssignments[2].Name = "modified-admin-assignment-cluster-1"
					mras[1].Spec.RoleAssignments[3].TargetNamespaces = append(
						mras[1].Spec.RoleAssignments[3].TargetNamespaces, "metrics")
					patchK8sResource(
						"multiclusterroleassignment", mras[1].Name, openClusterManagementGlobalSetNamespace, mras[1].Spec)

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentSingleRBName))
					mras[2].Spec.Subject.Name = "modified-user-single-rolebinding"
					mras[2].Spec.RoleAssignments[0].Name = "modified-test-role-assignment-namespaced"
					mras[2].Spec.RoleAssignments[0].ClusterSelection.ClusterNames = append(
						mras[2].Spec.RoleAssignments[0].ClusterSelection.ClusterNames, "managedcluster01", "managedcluster03")
					mras[2].Spec.RoleAssignments[0].TargetNamespaces = append(
						mras[2].Spec.RoleAssignments[0].TargetNamespaces, "staging", "prod")
					patchK8sResource(
						"multiclusterroleassignment", mras[2].Name, openClusterManagementGlobalSetNamespace, mras[2].Spec)

					By(fmt.Sprintf("Comprehensive modification of %s", testMulticlusterRoleAssignmentSingleCRBName))
					mras[3].Spec.Subject.Name = "modified-group-single-clusterrolebinding"
					mras[3].Spec.Subject.Kind = groupSubjectKind
					mras[3].Spec.RoleAssignments[0].Name = "modified-test-role-assignment"
					mras[3].Spec.RoleAssignments[0].ClusterRole = "admin"
					mras[3].Spec.RoleAssignments[0].TargetNamespaces = []string{"default", "kube-system", "applications"}
					mras[3].Spec.RoleAssignments[0].ClusterSelection.ClusterNames = append(
						mras[3].Spec.RoleAssignments[0].ClusterSelection.ClusterNames, "managedcluster02", "managedcluster03")
					patchK8sResource("multiclusterroleassignment", mras[3].Name,
						openClusterManagementGlobalSetNamespace, mras[3].Spec)

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
						{RoleName: "admin2", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "admin2", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
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
						{RoleName: "admin", Namespace: "default", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications", SubjectName: "modified-group-single-clusterrolebinding"},
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
						{RoleName: "admin2", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "admin2", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
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
						{RoleName: "admin", Namespace: "default", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications", SubjectName: "modified-group-single-clusterrolebinding"},
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
						{RoleName: "admin", Namespace: "default", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "kube-system", SubjectName: "modified-group-single-clusterrolebinding"},
						{RoleName: "admin", Namespace: "applications", SubjectName: "modified-group-single-clusterrolebinding"},
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
			Context("MulticlusterRoleAssignment validation after comprehensive modifications", func() {
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

				It("should have correct all clusters annotations for all comprehensively modified MRAs", func() {
					By("verifying all clusters annotations match targeted clusters for all comprehensively modified MRAs")
					for _, mra := range mras {
						validateMRAAllClustersAnnotation(mra)
					}
				})
			})
		})

		Context("should handle rapid overlapping PATCH operations and maintain consistency", func() {
			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple2Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
			})

			Context("resource creation and rapid patching", func() {
				var mraJSON string
				var clusterPermissionJSONs [3]string

				It("should create MRA and apply many overlapping PATCH operations", func() {
					By("creating MulticlusterRoleAssignment using multiple_2.yaml")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_2.yaml")

					By("fetching initial MulticlusterRoleAssignment")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple2Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)

					By("applying many overlapping PATCH operations in parallel")

					patches := []map[string]any{
						// Patch 1
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "admin-assignment-cluster-1", "clusterRole": "edit",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
						}}},
						// Patch 2
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{},
							{"name": "view-assignment-all-clusters", "clusterRole": "view",
								"clusterSelection": map[string]any{"type": "clusterNames",
									"clusterNames": []string{"managedcluster01", "managedcluster02"}}},
						}}},
						// Patch 3
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{}, {},
							{"name": "edit-assignment-single-namespace", "clusterRole": "edit",
								"targetNamespaces": []string{"default", "rapid-dev-1"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02"}}},
						}}},
						// Patch 4
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{}, {}, {},
							{"name": "monitoring-assignment-multi-namespace-single-cluster", "clusterRole": "admin",
								"targetNamespaces": []string{"monitoring", "observability"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster03"}}},
						}}},
						// Patch 5
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{}, {}, {}, {},
							{"name": "dev-assignment-single-namespace-multi-cluster", "clusterRole": "admin",
								"targetNamespaces": []string{"rapid-admin-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames",
									"clusterNames": []string{"managedcluster01"}}},
						}}},
						// Patch 6
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{}, {}, {}, {}, {},
							{"name": "logging-assignment-multi-namespace-multi-cluster", "clusterRole": "view",
								"targetNamespaces": []string{"development", "rapid-staging"},
								"clusterSelection": map[string]any{"type": "clusterNames",
									"clusterNames": []string{"managedcluster01", "managedcluster02"}}},
						}}},
						// Patch 7
						{"spec": map[string]any{"subject": map[string]any{"name": "rapid-user-1"}}},
						// Patch 8
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "new-admin-assignment", "clusterRole": "cluster-admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
							{"name": "new-edit-assignment", "clusterRole": "edit",
								"targetNamespaces": []string{"default", "rapid-dev-1", "rapid-dev-2"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02"}}},
						}}},
						// Patch 9
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "temp-admin", "clusterRole": "admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster03"}}},
							{"name": "temp-view", "clusterRole": "view",
								"targetNamespaces": []string{"temp-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
							{"name": "temp-edit", "clusterRole": "edit",
								"targetNamespaces": []string{"temp-edit-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 10
						{"spec": map[string]any{"subject": map[string]any{"kind": "Group"}}},
						// Patch 11
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "dynamic-admin", "clusterRole": "admin",
								"targetNamespaces": []string{"dynamic-ns-1", "dynamic-ns-2"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster02"}}},
						}}},
						// Patch 12
						{"spec": map[string]any{"subject": map[string]any{"name": "rapid-user-2"}}},
						// Patch 13
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "complex-assignment-1", "clusterRole": "view",
								"targetNamespaces": []string{"complex-ns-1"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
							{"name": "complex-assignment-2", "clusterRole": "edit",
								"targetNamespaces": []string{"complex-ns-2", "complex-ns-3"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02", "managedcluster03"}}},
							{"name": "complex-assignment-3", "clusterRole": "admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster03"}}},
						}}},
						// Patch 14
						{"spec": map[string]any{"subject": map[string]any{"name": "rapid-user-3", "kind": "User"}}},
						// Patch 15
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "override-assignment", "clusterRole": "cluster-admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 16
						{"spec": map[string]any{
							"subject": map[string]any{"name": "rapid-user-4", "kind": "Group"},
							"roleAssignments": []map[string]any{
								{"name": "combo-assignment", "clusterRole": "edit",
									"targetNamespaces": []string{"combo-ns"},
									"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
										"managedcluster02"}}},
							},
						}},
						// Patch 17
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "penultimate-assignment", "clusterRole": "view",
								"targetNamespaces": []string{"penultimate-ns-1", "penultimate-ns-2"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster03"}}},
						}}},
						// Patch 18
						{"spec": map[string]any{"subject": map[string]any{"name": "rapid-group-temp"}}},
						// Patch 19
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "pre-final-assignment", "clusterRole": "admin",
								"targetNamespaces": []string{"pre-final-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 20
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-assignment-20", "clusterRole": "view",
								"targetNamespaces": []string{"chaos-ns-20"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
						}}},
						// Patch 21
						{"spec": map[string]any{"subject": map[string]any{"name": "chaos-user-21"}}},
						// Patch 22
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-22-admin", "clusterRole": "admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster02"}}},
							{"name": "chaos-22-edit", "clusterRole": "edit",
								"targetNamespaces": []string{"chaos-22-ns1", "chaos-22-ns2"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster03"}}},
						}}},
						// Patch 23
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "admin-assignment-cluster-1", "clusterRole": "cluster-admin",
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
						}}},
						// Patch 24
						{"spec": map[string]any{
							"subject": map[string]any{"name": "chaos-group-24", "kind": "Group"},
							"roleAssignments": []map[string]any{
								{"name": "chaos-24-view", "clusterRole": "view",
									"targetNamespaces": []string{"chaos-24-ns"},
									"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
										"managedcluster02", "managedcluster03"}}},
							},
						}},
						// Patch 25
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-25-1", "clusterRole": "view", "clusterSelection": map[string]any{
								"type": "clusterNames", "clusterNames": []string{"managedcluster01"}}},
							{"name": "chaos-25-2", "clusterRole": "edit", "clusterSelection": map[string]any{
								"type": "clusterNames", "clusterNames": []string{"managedcluster02"}}},
							{"name": "chaos-25-3", "clusterRole": "admin", "clusterSelection": map[string]any{
								"type": "clusterNames", "clusterNames": []string{"managedcluster03"}}},
							{"name": "chaos-25-4", "clusterRole": "view", "targetNamespaces": []string{"chaos-25-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 26
						{"spec": map[string]any{"subject": map[string]any{"name": "chaos-user-26", "kind": "User"}}},
						// Patch 27
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-27-assignment", "clusterRole": "edit",
								"targetNamespaces": []string{"chaos-27-ns1", "chaos-27-ns2", "chaos-27-ns3"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster03"}}},
						}}},
						// Patch 28
						{"spec": map[string]any{"subject": map[string]any{"kind": "Group"}}},
						// Patch 29
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-29-multi-ns", "clusterRole": "view",
								"targetNamespaces": []string{"chaos-29-ns1", "chaos-29-ns2", "chaos-29-ns3",
									"chaos-29-ns4", "chaos-29-ns5"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02"}}},
						}}},
						// Patch 30
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-30-cluster", "clusterRole": "cluster-admin",
								"clusterSelection": map[string]any{"type": "clusterNames",
									"clusterNames": []string{"managedcluster01"}}},
							{"name": "chaos-30-namespaced", "clusterRole": "admin",
								"targetNamespaces": []string{"chaos-30-ns"}, "clusterSelection": map[string]any{
									"type": "clusterNames", "clusterNames": []string{
										"managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 31
						{"spec": map[string]any{"subject": map[string]any{"name": "chaos-user-31"}}},
						// Patch 32
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-32-single", "clusterRole": "edit",
								"targetNamespaces": []string{"chaos-32-single-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster02", "managedcluster03"}}},
						}}},
						// Patch 33
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-33-admin", "clusterRole": "admin", "clusterSelection": map[string]any{
								"type": "clusterNames", "clusterNames": []string{"managedcluster01"}}},
							{"name": "chaos-33-edit-ns", "clusterRole": "edit", "targetNamespaces": []string{
								"chaos-33-ns1", "chaos-33-ns2"}, "clusterSelection": map[string]any{
								"type": "clusterNames", "clusterNames": []string{"managedcluster02"}}},
							{"name": "chaos-33-view-multi", "clusterRole": "view",
								"targetNamespaces": []string{"chaos-33-ns3"}, "clusterSelection": map[string]any{
									"type": "clusterNames", "clusterNames": []string{
										"managedcluster01", "managedcluster03"}}},
						}}},
						// Patch 34
						{"spec": map[string]any{
							"subject": map[string]any{"name": "chaos-group-34", "kind": "Group"},
							"roleAssignments": []map[string]any{
								{"name": "chaos-34-simple", "clusterRole": "view", "clusterSelection": map[string]any{
									"type": "clusterNames", "clusterNames": []string{"managedcluster02"}}},
							},
						}},
						// Patch 35
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-35-1", "clusterRole": "view", "targetNamespaces": []string{"chaos-35-1"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01"}}},
							{"name": "chaos-35-2", "clusterRole": "view", "targetNamespaces": []string{"chaos-35-2"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster02"}}},
							{"name": "chaos-35-3", "clusterRole": "view", "targetNamespaces": []string{"chaos-35-3"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster03"}}},
						}}},
						// Patch 36
						{"spec": map[string]any{"subject": map[string]any{"name": "chaos-user-36", "kind": "User"}}},
						// Patch 37
						{"spec": map[string]any{"roleAssignments": []map[string]any{
							{"name": "chaos-37-duplicate", "clusterRole": "admin",
								"targetNamespaces": []string{"chaos-37-ns"},
								"clusterSelection": map[string]any{"type": "clusterNames", "clusterNames": []string{
									"managedcluster01", "managedcluster01", "managedcluster02"}}},
						}}},
						// Patch 38
						{"spec": map[string]any{"roleAssignments": []map[string]any{}}},
						// Patch 39
						{"spec": map[string]any{"subject": map[string]any{
							"name": "chaos-pre-final-39", "kind": "Group"}}},
					}

					var parallelPatchCommands []string

					for i, patch := range patches {
						patchBytes, err := json.Marshal(patch)
						Expect(err).NotTo(HaveOccurred())

						// Escape single quotes in JSON for bash
						patchStr := strings.ReplaceAll(string(patchBytes), "'", "'\"'\"'")

						// Create kubectl patch command with background execution (&)
						cmd := fmt.Sprintf("kubectl patch multiclusterroleassignment %s -n %s --type merge -p '%s' &",
							mra.Name, openClusterManagementGlobalSetNamespace, patchStr)
						parallelPatchCommands = append(parallelPatchCommands, cmd)

						By(fmt.Sprintf("Queuing parallel patch %d", i+1))
					}

					// Execute patches in parallel and wait for completion
					parallelCommands := strings.Join(parallelPatchCommands, " ") + " wait"

					By("Executing patches in parallel to create resource version conflicts")
					bashCmd := exec.Command("bash", "-c", parallelCommands)
					_, err := utils.Run(bashCmd)
					Expect(err).NotTo(HaveOccurred())

					By("Applying final deterministic patch sequentially")
					finalMRA := mra.DeepCopy()
					finalMRA.Spec.Subject.Name = "rapid-final-group"
					finalMRA.Spec.Subject.Kind = "Group"
					finalMRA.Spec.RoleAssignments = []rbacv1alpha1.RoleAssignment{
						{
							Name:        "admin-assignment-cluster-1",
							ClusterRole: "view",
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{"managedcluster01", "managedcluster02", "managedcluster03"},
							},
						},
						{
							Name:             "edit-assignment-single-namespace",
							ClusterRole:      "edit",
							TargetNamespaces: []string{"default", "rapid-dev-1", "rapid-dev-2", "rapid-final-ns"},
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{"managedcluster02", "managedcluster03"},
							},
						},
						{
							Name:             "monitoring-assignment-multi-namespace-single-cluster",
							ClusterRole:      "admin",
							TargetNamespaces: []string{"monitoring", "observability"},
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{"managedcluster03"},
							},
						},
						{
							Name:             "dev-assignment-single-namespace-multi-cluster",
							ClusterRole:      "admin",
							TargetNamespaces: []string{"rapid-admin-ns"},
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{"managedcluster01"},
							},
						},
						{
							Name:        "logging-assignment-multi-namespace-multi-cluster",
							ClusterRole: "view",
							TargetNamespaces: []string{
								"development", "rapid-staging", "logging", "kube-system", "rapid-prod", "rapid-test"},
							ClusterSelection: rbacv1alpha1.ClusterSelection{
								Type:         "clusterNames",
								ClusterNames: []string{"managedcluster01", "managedcluster02", "managedcluster03"},
							},
						},
					}

					patchK8sResource(
						"multiclusterroleassignment", finalMRA.Name, openClusterManagementGlobalSetNamespace, finalMRA.Spec)

					By("fetching final MulticlusterRoleAssignment state")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentMultiple2Name, openClusterManagementGlobalSetNamespace)
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch final ClusterPermissions from all managed clusters", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf("fetching final ClusterPermission from %s after rapid patching", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON("clusterpermissions",
							"mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling final ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])
					}
				})
			})

			//nolint:dupl
			Context("ClusterPermission validation after rapid patching", func() {
				It("should have correct content for managedcluster01 after rapid patching", func() {
					By("verifying ClusterPermission content in managedcluster01 namespace after rapid patching")
					Expect(clusterPermissions[0].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[0].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.RoleBindings).To(HaveLen(7))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "rapid-final-group"},
						// RoleBindings
						{RoleName: "admin", Namespace: "rapid-admin-ns", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "development", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-staging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "logging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-prod", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-test", SubjectName: "rapid-final-group"},
					}
					validateClusterPermissionBindings(clusterPermissions[0], expectedBindings)
				})

				It("should have correct content for managedcluster02 after rapid patching", func() {
					By("verifying ClusterPermission content in managedcluster02 namespace after rapid patching")
					Expect(clusterPermissions[1].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[1].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.RoleBindings).To(HaveLen(10))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "rapid-final-group"},
						// RoleBindings
						{RoleName: "edit", Namespace: "default", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-dev-1", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-dev-2", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-final-ns", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "development", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-staging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "logging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-prod", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-test", SubjectName: "rapid-final-group"},
					}
					validateClusterPermissionBindings(clusterPermissions[1], expectedBindings)
				})

				It("should have correct content for managedcluster03 after rapid patching", func() {
					By("verifying ClusterPermission content in managedcluster03 namespace after rapid patching")
					Expect(clusterPermissions[2].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[2].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.RoleBindings).To(HaveLen(12))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "view", Namespace: "", SubjectName: "rapid-final-group"},
						// RoleBindings
						{RoleName: "edit", Namespace: "default", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-dev-1", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-dev-2", SubjectName: "rapid-final-group"},
						{RoleName: "edit", Namespace: "rapid-final-ns", SubjectName: "rapid-final-group"},
						{RoleName: "admin", Namespace: "monitoring", SubjectName: "rapid-final-group"},
						{RoleName: "admin", Namespace: "observability", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "development", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-staging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "logging", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-prod", SubjectName: "rapid-final-group"},
						{RoleName: "view", Namespace: "rapid-test", SubjectName: "rapid-final-group"},
					}
					validateClusterPermissionBindings(clusterPermissions[2], expectedBindings)
				})

				It("should have correct owner annotations for all clusters after rapid patching", func() {
					By("verifying ClusterPermission owner annotations for all clusters after rapid patching")
					for _, cp := range clusterPermissions {
						validateMRAOwnerAnnotations(cp, mra)
					}

					By("verifying binding annotations have semantic consistency after rapid patching")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
					}
				})
			})

			Context("MulticlusterRoleAssignment validation after rapid patching", func() {
				It("should have correct conditions after rapid patching", func() {
					By("verifying MulticlusterRoleAssignment conditions after rapid patching")
					validateMRASuccessConditions(mra)
				})

				It("should have correct role assignment statuses after rapid patching", func() {
					By("verifying all role assignment status details after rapid patching")
					Expect(mra.Status.RoleAssignments).To(HaveLen(5))

					roleAssignmentsByName := mapRoleAssignmentsByName(mra)

					for _, roleAssignmentStatus := range mra.Status.RoleAssignments {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName, roleAssignmentStatus.Name)
					}
				})

				It("should have correct all clusters annotation after rapid patching", func() {
					By("verifying all clusters annotation matches targeted clusters after rapid patching")
					validateMRAAllClustersAnnotation(mra)
				})
			})
		})

		Context("should delete MulticlusterRoleAssignments and update ClusterPermissions - tests MRA deletion "+
			"with shared ClusterPermissions", func() {

			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
			var mras [4]rbacv1alpha1.MulticlusterRoleAssignment

			Context("resource creation and deletion", func() {
				var mraJSONs [4]string
				var clusterPermissionJSONs [3]string

				It("should create all MulticlusterRoleAssignments in sequence", func() {
					By("creating all MulticlusterRoleAssignments sequentially to test CREATE and DELETE operations")
					manifestFiles := []string{
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_1.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml",
					}
					for _, manifestFile := range manifestFiles {
						applyK8sManifest(manifestFile)
					}
				})

				It("should delete one MulticlusterRoleAssignment", func() {
					By(fmt.Sprintf("deleting %s", testMulticlusterRoleAssignmentMultiple2Name))
					deleteK8sMRA(testMulticlusterRoleAssignmentMultiple2Name)
				})

				It("should fetch remaining MulticlusterRoleAssignments", func() {
					By("fetching remaining three MulticlusterRoleAssignments")
					mraNames := []string{
						testMulticlusterRoleAssignmentMultiple1Name,
						testMulticlusterRoleAssignmentSingleRBName,
						testMulticlusterRoleAssignmentSingleCRBName,
					}
					for i, mraName := range mraNames {
						mraJSONs[i+1] = fetchK8sResourceJSON(
							"multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
					}

					By("unmarshaling remaining MulticlusterRoleAssignment JSONs")
					for i := 1; i < len(mras); i++ {
						unmarshalJSON(mraJSONs[i], &mras[i])
					}
				})

				It("should fetch updated ClusterPermissions for all managed clusters", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf(
							"waiting for updated ClusterPermission to be ready and fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON("clusterpermissions",
							"mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])
					}
				})
			})

			Context("ClusterPermission updated content validation after deletion", func() {
				It("should have correctly updated content for managedcluster01 after deletion", func() {
					By("verifying updated ClusterPermission content in managedcluster01 namespace")
					Expect(clusterPermissions[0].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.ClusterRoleBindings).To(HaveLen(2))
					Expect(clusterPermissions[0].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[0].Spec.RoleBindings).To(HaveLen(4))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "admin", Namespace: "", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
						// RoleBindings
						{RoleName: "view", Namespace: "default", SubjectName: "test-user-multiple-1"},
						{RoleName: "view", Namespace: "kube-system", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[0], expectedBindings)
				})

				It("should have correctly updated content for managedcluster02 after deletion", func() {
					By("verifying updated ClusterPermission content in managedcluster02 namespace")
					Expect(clusterPermissions[1].Spec.ClusterRoleBindings).To(BeNil())
					Expect(clusterPermissions[1].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[1].Spec.RoleBindings).To(HaveLen(9))

					expectedBindings := []ExpectedBinding{
						// RoleBindings
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

				It("should have correctly updated content for managedcluster03 after deletion", func() {
					By("verifying updated ClusterPermission content in managedcluster03 namespace")
					Expect(clusterPermissions[2].Spec.ClusterRoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermissions[2].Spec.RoleBindings).NotTo(BeNil())
					Expect(*clusterPermissions[2].Spec.RoleBindings).To(HaveLen(2))

					expectedBindings := []ExpectedBinding{
						// ClusterRoleBindings
						{RoleName: "edit", Namespace: "", SubjectName: "test-user-multiple-1"},
						// RoleBindings
						{RoleName: "system:mon", Namespace: "monitoring", SubjectName: "test-user-multiple-1"},
						{RoleName: "system:mon", Namespace: "observability", SubjectName: "test-user-multiple-1"},
					}
					validateClusterPermissionBindings(clusterPermissions[2], expectedBindings)
				})

				It("should have correct owner annotations for all clusters after deletion", func() {
					By("verifying ClusterPermission owner annotations for remaining MRAs")
					for _, cp := range clusterPermissions {
						for i := 1; i < len(mras); i++ {
							validateMRAOwnerAnnotations(cp, mras[i])
						}
					}

					By("verifying binding annotations have semantic consistency after deletion")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, mras[1:])
					}
				})
			})

			Context("MulticlusterRoleAssignment validation after deletion", func() {
				It("should verify deleted MRA no longer exists", func() {
					By(fmt.Sprintf("verifying %s is deleted", testMulticlusterRoleAssignmentMultiple2Name))
					verifyK8sResourceDeleted("multiclusterroleassignment", testMulticlusterRoleAssignmentMultiple2Name,
						openClusterManagementGlobalSetNamespace)
				})

				It("should have correct conditions for remaining MRAs", func() {
					By("verifying MulticlusterRoleAssignment conditions for remaining MRAs")
					for i := 1; i < len(mras); i++ {
						validateMRASuccessConditions(mras[i])
					}
				})

				It("should have correct role assignment statuses for remaining MRAs", func() {
					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentMultiple1Name))
					Expect(mras[1].Status.RoleAssignments).To(HaveLen(4))
					roleAssignmentsByName1 := mapRoleAssignmentsByName(mras[1])
					assignmentNames1 := []string{
						"view-assignment-namespaced-clusters-1-2",
						"edit-assignment-cluster-3",
						"admin-assignment-cluster-1",
						"monitoring-assignment-namespaced-all-clusters",
					}
					for _, name := range assignmentNames1 {
						validateRoleAssignmentSuccessStatus(roleAssignmentsByName1, name)
					}

					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentSingleRBName))
					Expect(mras[2].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName2 := mapRoleAssignmentsByName(mras[2])
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName2, "test-role-assignment-namespaced")

					By(fmt.Sprintf(
						"verifying role assignment status details for %s", testMulticlusterRoleAssignmentSingleCRBName))
					Expect(mras[3].Status.RoleAssignments).To(HaveLen(1))
					roleAssignmentsByName3 := mapRoleAssignmentsByName(mras[3])
					validateRoleAssignmentSuccessStatus(roleAssignmentsByName3, "test-role-assignment")
				})

				It("should have correct all clusters annotations for remaining MRAs", func() {
					By("verifying all clusters annotations match targeted clusters for remaining MRAs")
					for i := 1; i < len(mras); i++ {
						validateMRAAllClustersAnnotation(mras[i])
					}
				})
			})

			Context("final deletion of all remaining MRAs", func() {
				mraNames := []string{
					testMulticlusterRoleAssignmentMultiple1Name,
					testMulticlusterRoleAssignmentSingleRBName,
					testMulticlusterRoleAssignmentSingleCRBName,
				}

				It("should delete all remaining MulticlusterRoleAssignments", func() {
					By("deleting remaining MulticlusterRoleAssignments one by one")
					for _, mraName := range mraNames {
						By(fmt.Sprintf("deleting %s", mraName))
						deleteK8sMRA(mraName)
					}
				})

				It("should verify all MulticlusterRoleAssignments are deleted", func() {
					By("verifying all MRAs no longer exist")
					for _, mraName := range mraNames {
						By(fmt.Sprintf("verifying %s is deleted", mraName))
						verifyK8sResourceDeleted("multiclusterroleassignment", mraName, openClusterManagementGlobalSetNamespace)
					}
				})

				It("should verify all ClusterPermissions are deleted", func() {
					By("verifying all managed ClusterPermissions are deleted")
					clusterNames := []string{"managedcluster01", "managedcluster02", "managedcluster03"}

					for _, clusterName := range clusterNames {
						By(fmt.Sprintf("verifying ClusterPermission is deleted in %s", clusterName))
						verifyK8sResourceDeleted("clusterpermissions", "mra-managed-permissions", clusterName)
					}
				})
			})
		})

		Context("should reconcile ClusterPermission when manually modified - tests drift correction", func() {
			var clusterPermission clusterpermissionv1alpha1.ClusterPermission
			var mra rbacv1alpha1.MulticlusterRoleAssignment
			var initialCPGeneration int64

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("MRA creation and resource fetching", func() {
				var clusterPermissionJSON, mraJSON string

				It("should create and fetch MulticlusterRoleAssignment", func() {
					By("creating a MulticlusterRoleAssignment with one ClusterRoleBinding")
					applyK8sManifest("config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml")

					By("waiting for MulticlusterRoleAssignment to be created and fetching it")
					mraJSON = fetchK8sResourceJSON("multiclusterroleassignment",
						testMulticlusterRoleAssignmentSingleCRBName, openClusterManagementGlobalSetNamespace)

					By("unmarshaling MulticlusterRoleAssignment json")
					unmarshalJSON(mraJSON, &mra)
				})

				It("should fetch initial ClusterPermission", func() {
					By("waiting for ClusterPermission to be created and fetching it")
					clusterPermissionJSON = fetchK8sResourceJSON(
						"clusterpermissions", "mra-managed-permissions", "managedcluster01")

					By("unmarshaling ClusterPermission json")
					unmarshalJSON(clusterPermissionJSON, &clusterPermission)

					By("storing initial generation")
					initialCPGeneration = clusterPermission.Generation
				})
			})

			Context("drift correction after manual modification", func() {
				It("should manually modify ClusterPermission to simulate drift", func() {
					By("modifying the ClusterPermission to change role from 'view' to 'edit'")
					(*clusterPermission.Spec.ClusterRoleBindings)[0].RoleRef.Name = "edit"
					patchK8sResource(
						"clusterpermissions", clusterPermission.Name, clusterPermission.Namespace, clusterPermission.Spec)
				})

				It("fetch ClusterPermission and validate generation change", func() {
					By("fetching final reconciled ClusterPermission")
					reconciledJSON := fetchK8sResourceJSON(
						"clusterpermissions", "mra-managed-permissions", "managedcluster01")
					unmarshalJSON(reconciledJSON, &clusterPermission)

					By("verifying generation incremented after manual modification")
					Expect(clusterPermission.Generation).To(BeNumerically(">", initialCPGeneration))
				})

				It("should have correct ClusterRoleBinding after drift correction", func() {
					By("verifying ClusterPermission has correct ClusterRoleBinding after reconciliation")
					Expect(*clusterPermission.Spec.ClusterRoleBindings).To(HaveLen(1))
					Expect(clusterPermission.Spec.RoleBindings).To(BeNil())

					expectedBindings := []ExpectedBinding{
						{RoleName: "view", Namespace: "", SubjectName: "test-user-single-clusterrolebinding"},
					}
					validateClusterPermissionBindings(clusterPermission, expectedBindings)
				})

				It("should have correct owner annotations after drift correction", func() {
					By("verifying ClusterPermission has correct owner annotations")
					validateMRAOwnerAnnotations(clusterPermission, mra)

					By("verifying binding annotations have semantic consistency")
					validateBindingConsistency(clusterPermission, []rbacv1alpha1.MulticlusterRoleAssignment{mra})
				})
			})
		})

		Context("should reconcile ClusterPermission when manually modified with multiple MRAs - tests complex drift "+
			"correction", func() {

			var clusterPermissions [3]clusterpermissionv1alpha1.ClusterPermission
			var mras [4]rbacv1alpha1.MulticlusterRoleAssignment
			var initialCPGenerations [3]int64

			AfterAll(func() {
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple2Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
				cleanupTestResources(testMulticlusterRoleAssignmentMultiple1Name, []string{
					"managedcluster01", "managedcluster02", "managedcluster03"})
				cleanupTestResources(testMulticlusterRoleAssignmentSingleRBName, []string{"managedcluster02"})
				cleanupTestResources(testMulticlusterRoleAssignmentSingleCRBName, []string{"managedcluster01"})
			})

			Context("MRA creation and resource fetching", func() {
				var mraJSONs [4]string
				var clusterPermissionJSONs [3]string

				It("should create and fetch all MulticlusterRoleAssignments in sequence", func() {
					By("creating all MulticlusterRoleAssignments sequentially")
					manifestFiles := []string{
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_multiple_1.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_2.yaml",
						"config/samples/rbac_v1alpha1_multiclusterroleassignment_single_1.yaml",
					}
					for _, manifestFile := range manifestFiles {
						applyK8sManifest(manifestFile)
					}

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

				It("should fetch initial ClusterPermissions for all managed clusters", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf(
							"waiting for merged ClusterPermission to be ready and fetching it from %s", clusterName))
						clusterPermissionJSONs[i-1] = fetchK8sResourceJSON(
							"clusterpermissions", "mra-managed-permissions", clusterName)

						By(fmt.Sprintf("unmarshaling ClusterPermission json for %s", clusterName))
						unmarshalJSON(clusterPermissionJSONs[i-1], &clusterPermissions[i-1])

						By(fmt.Sprintf("storing initial generation for %s", clusterName))
						initialCPGenerations[i-1] = clusterPermissions[i-1].Generation
					}
				})
			})

			//nolint:dupl
			Context("drift correction after radical manual modifications", func() {
				It("should manually modify ClusterPermissions with various drift scenarios", func() {
					By("modifying managedcluster01 ClusterPermission")
					(*clusterPermissions[0].Spec.ClusterRoleBindings)[0].RoleRef.Name = "cluster-admin"
					(*clusterPermissions[0].Spec.RoleBindings)[0].RoleRef.Name = "admin"
					*clusterPermissions[0].Spec.ClusterRoleBindings = slices.Delete(
						*clusterPermissions[0].Spec.ClusterRoleBindings, 1, 2)

					orphanedBinding := clusterpermissionv1alpha1.ClusterRoleBinding{
						Name: "orphaned-binding",
						RoleRef: &rbacv1.RoleRef{
							Kind:     "ClusterRole",
							Name:     "cluster-admin",
							APIGroup: "rbac.authorization.k8s.io",
						},
						Subjects: []rbacv1.Subject{{Kind: "User", Name: "orphaned-user"}},
					}

					*clusterPermissions[0].Spec.ClusterRoleBindings = append(
						*clusterPermissions[0].Spec.ClusterRoleBindings, orphanedBinding)

					patchK8sResource("clusterpermissions", clusterPermissions[0].Name, clusterPermissions[0].Namespace,
						clusterPermissions[0].Spec)

					By("modifying managedcluster02 ClusterPermission")
					*clusterPermissions[1].Spec.RoleBindings = slices.Delete(
						*clusterPermissions[1].Spec.RoleBindings, 0, 3)
					(*clusterPermissions[1].Spec.RoleBindings)[0].Subjects[0].Name = "blah-blah-user"

					orphanedRoleBinding := clusterpermissionv1alpha1.RoleBinding{
						Name:      "orphaned-rolebinding",
						Namespace: "default",
						RoleRef: clusterpermissionv1alpha1.RoleRef{
							Kind:     "ClusterRole",
							Name:     "cluster-admin",
							APIGroup: "rbac.authorization.k8s.io",
						},
						Subjects: []rbacv1.Subject{{Kind: "User", Name: "orphaned-user"}},
					}

					*clusterPermissions[1].Spec.RoleBindings = append(
						*clusterPermissions[1].Spec.RoleBindings, orphanedRoleBinding)

					patchK8sResource("clusterpermissions", clusterPermissions[1].Name,
						clusterPermissions[1].Namespace, clusterPermissions[1].Spec)

					By("modifying managedcluster03 ClusterPermission")
					emptyClusterRoleBindings := []clusterpermissionv1alpha1.ClusterRoleBinding{}
					clusterPermissions[2].Spec.ClusterRoleBindings = &emptyClusterRoleBindings

					emptyRoleBindings := []clusterpermissionv1alpha1.RoleBinding{}
					clusterPermissions[2].Spec.RoleBindings = &emptyRoleBindings

					patchK8sResource("clusterpermissions", clusterPermissions[2].Name, clusterPermissions[2].Namespace,
						clusterPermissions[2].Spec)
				})

				It("should fetch ClusterPermissions and validate generation changes", func() {
					for i := 1; i <= 3; i++ {
						clusterName := fmt.Sprintf("managedcluster%02d", i)
						By(fmt.Sprintf("fetching reconciled ClusterPermission from %s", clusterName))
						reconciledJSON := fetchK8sResourceJSON("clusterpermissions", "mra-managed-permissions", clusterName)
						unmarshalJSON(reconciledJSON, &clusterPermissions[i-1])

						By(fmt.Sprintf("verifying generation incremented for %s", clusterName))
						Expect(clusterPermissions[i-1].Generation).To(BeNumerically(">", initialCPGenerations[i-1]))
					}
				})

				It("should have correctly merged content for managedcluster01 after drift correction", func() {
					By("verifying ClusterPermission was fully restored in managedcluster01")
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

				It("should have correctly merged content for managedcluster02 after drift correction", func() {
					By("verifying ClusterPermission was fully restored in managedcluster02")
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

				It("should have correctly merged content for managedcluster03 after drift correction", func() {
					By("verifying ClusterPermission was fully restored in managedcluster03")
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

				It("should have correct owner annotations for all clusters after drift correction", func() {
					By("verifying ClusterPermission owner annotations restored for all clusters")
					for _, cp := range clusterPermissions {
						for _, mra := range mras {
							validateMRAOwnerAnnotations(cp, mra)
						}
					}

					By("verifying binding annotations have semantic consistency after drift correction")
					for _, cp := range clusterPermissions {
						validateBindingConsistency(cp, mras[:])
					}
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
	// Ensure CreatedAt is set (non-zero time)
	Expect(assignment.CreatedAt.IsZero()).To(BeFalse())
}

// applyK8sManifest applies a Kubernetes manifest file using kubectl.
func applyK8sManifest(manifestPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", manifestPath)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
	waitForController()
}

// patchK8sResource applies a spec patch to a Kubernetes resource using kubectl patch.
func patchK8sResource(resourceType, resourceName, namespace string, spec any) {
	patchSpec := map[string]any{
		"spec": spec,
	}
	patchBytes, err := json.Marshal(patchSpec)
	Expect(err).NotTo(HaveOccurred())

	cmd := exec.Command(
		"kubectl", "patch", resourceType, resourceName, "-n", namespace, "--type", "merge", "-p", string(patchBytes))
	_, err = utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
	waitForController()
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

// deleteK8sMRA deletes a MulticlusterRoleAssignment using kubectl delete.
func deleteK8sMRA(mraName string) {
	cmd := exec.Command("kubectl", "delete", "multiclusterroleassignment",
		mraName, "-n", openClusterManagementGlobalSetNamespace)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
	waitForController()
}

// verifyK8sResourceDeleted verifies that a Kubernetes resource has been deleted by checking it returns "not found".
func verifyK8sResourceDeleted(resourceType, resourceName, namespace string) {
	Eventually(func(g Gomega) {
		cmd := exec.Command("kubectl", "get", resourceType, resourceName, "-n", namespace)
		_, err := utils.Run(cmd)
		g.Expect(err).To(HaveOccurred())
		g.Expect(err.Error()).To(ContainSubstring("not found"))
	}, 20*time.Second).Should(Succeed())
}

// waitForController sleeps for 1 seccond.
func waitForController() {
	time.Sleep(1 * time.Second)
}

// cleanupTestResources cleans up MulticlusterRoleAssignment and ClusterPermissions for a test. Skips cleanup if the
// current test context has failures to preserve state for debugging.
func cleanupTestResources(mraName string, clusterNames []string) {
	specReport := CurrentSpecReport()
	if specReport.Failed() {
		By("Skipping cleanup due to test failure - preserving state for debugging")
		return
	}

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

// validateMRAAllClustersAnnotation validates that the MulticlusterRoleAssignment contains the correct all clusters
// annotation that matches the clusters targeted in its role assignments.
func validateMRAAllClustersAnnotation(mra rbacv1alpha1.MulticlusterRoleAssignment) {
	const allClustersAnnotation = "clusters.rbac.open-cluster-management.io"

	expectedClusters := getTargetedClustersFromMRA(mra)
	Expect(expectedClusters).NotTo(BeEmpty(),
		fmt.Sprintf("MRA %s/%s has no target clusters - this should not happen", mra.Namespace, mra.Name))

	if mra.Annotations == nil {
		Expect(mra.Annotations).NotTo(BeNil(),
			fmt.Sprintf(
				"Expected all clusters annotation for MRA %s/%s, but annotations are nil", mra.Namespace, mra.Name))
	}

	actualAnnotationValue, exists := mra.Annotations[allClustersAnnotation]

	Expect(exists).To(BeTrue(),
		fmt.Sprintf(
			"Expected all clusters annotation for MRA %s/%s, but annotation not found", mra.Namespace, mra.Name))

	Expect(actualAnnotationValue).NotTo(BeEmpty(),
		fmt.Sprintf("All clusters annotation for MRA %s/%s exists but is empty - this should not happen", mra.Namespace,
			mra.Name))

	actualClusters := strings.Split(actualAnnotationValue, ";")

	slices.Sort(expectedClusters)
	slices.Sort(actualClusters)

	Expect(actualClusters).To(Equal(expectedClusters), fmt.Sprintf(
		"Expected all clusters annotation '%s' for MRA %s/%s, but got '%s'", strings.Join(expectedClusters, ";"),
		mra.Namespace, mra.Name, actualAnnotationValue))
}

// getTargetedClustersFromMRA extracts all unique cluster names targeted by the MRA's role assignments.
func getTargetedClustersFromMRA(mra rbacv1alpha1.MulticlusterRoleAssignment) []string {
	var uniqueClusters []string
	clusterMap := make(map[string]bool)
	for _, roleAssignment := range mra.Spec.RoleAssignments {
		for _, clusterName := range roleAssignment.ClusterSelection.ClusterNames {
			if !clusterMap[clusterName] {
				clusterMap[clusterName] = true
				uniqueClusters = append(uniqueClusters, clusterName)
			}
		}
	}
	return uniqueClusters
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
