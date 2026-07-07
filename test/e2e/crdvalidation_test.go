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
	"fmt"
	"os"
	"os/exec"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stolostron/multicluster-role-assignment/test/utils"
)

const (
	rbacAPIGroup       = "rbac.authorization.k8s.io"
	userKind           = "User"
	groupKind          = "Group"
	serviceAccountKind = "ServiceAccount"
	noAPIGroup         = ""
	noNamespace        = ""
)

var _ = Describe("CRD Validation", Ordered, func() {
	BeforeEach(func() {
		cleanupCRDValidationTestMRA()
	})

	AfterEach(func() {
		cleanupCRDValidationTestMRA()
	})

	Context("spec.roleAssignments[].clusterRole validation", func() {
		DescribeTable("validation cases",
			func(roleName string, shouldSucceed bool) {
				yamlPath := createTestMRAWithClusterRole(roleName)
				defer func() { _ = os.Remove(yamlPath) }()

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},
			// Valid cases
			Entry("should accept standard role names", "view", true),
			Entry("should accept names with hyphens", "cluster-admin", true),
			Entry("should accept names with dots", "example.com", true),
			Entry("should accept role with dots and underscores", "my.special_role", true),
			Entry("should accept names with colons (system roles)", "system:admin", true),
			Entry("should accept complex system role names", "system:controller:generic-garbage-collector", true),
			Entry("should accept names with underscores", "my_role", true),
			Entry("should accept names with @ symbols", "user@example.com", true),
			Entry("should accept uppercase characters", "MyRole", true),
			Entry("should accept mixed case and special chars", "System:ServiceAccount:Namespace:Name", true),
			Entry("should accept complex characters allowed by K8s RBAC", "my-role.v1_alpha:test", true),

			// Invalid cases
			Entry("should reject empty names", "", false),
		)
	})

	Context("spec.roleAssignments[].targetNamespaces validation", func() {
		DescribeTable("validation cases",
			func(namespaces []string, shouldSucceed bool) {
				yamlPath := createTestMRAWithTargetNamespace(namespaces...)
				defer func() { _ = os.Remove(yamlPath) }()

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},
			// Valid cases
			Entry("should accept lowercase alphanumeric names", []string{"default"}, true),
			Entry("should accept names with hyphens", []string{"my-namespace"}, true),
			Entry("should accept names with numbers", []string{"namespace-123"}, true),
			Entry("should accept single character names", []string{"a"}, true),
			Entry("should accept numbers at start and end", []string{"1ns2"}, true),
			Entry("should accept all numbers", []string{"123456"}, true),
			Entry("should accept mixed alphanumeric with hyphens", []string{"my-app-namespace-1"}, true),
			Entry("should accept names up to 63 characters", []string{strings.Repeat("a", 63)}, true),
			Entry("should accept multiple valid namespaces", []string{"default", "kube-system", "my-app-ns"}, true),

			// Invalid cases
			Entry("should reject names with uppercase characters", []string{"MyNamespace"}, false),
			Entry("should reject names with underscores", []string{"my_namespace"}, false),
			Entry("should reject names with dots", []string{"my.namespace"}, false),
			Entry("should reject names starting with hyphen", []string{"-invalid"}, false),
			Entry("should reject names ending with hyphen", []string{"invalid-"}, false),
			Entry("should reject names with special characters", []string{"namespace@test"}, false),
			Entry("should reject names with spaces", []string{"my namespace"}, false),
			Entry("should reject empty names", []string{""}, false),
			Entry("should reject names exceeding 63 characters", []string{strings.Repeat("a", 64)}, false),
			Entry("should reject if any namespace in list is invalid", []string{"default", "Invalid-NS", "my-app-ns"}, false),
		)
	})

	Context("spec.roleAssignments[].clusterSelection.placements[].name validation", func() {
		DescribeTable("validation cases",
			func(placementName string, shouldSucceed bool) {
				yamlPath := createTestMRAWithPlacementName(placementName)
				defer func() { _ = os.Remove(yamlPath) }()

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},
			// Valid cases
			Entry("should accept lowercase alphanumeric names", "placement1", true),
			Entry("should accept names with hyphens", "my-placement", true),
			Entry("should accept names with dots (DNS subdomain)", "example.com", true),
			Entry("should accept names with numbers", "placement-123", true),
			Entry("should accept single character names", "a", true),
			Entry("should accept DNS subdomain with multiple segments", "subdomain.example.com", true),
			Entry("should accept numbers at start and end", "1placement2", true),
			Entry("should accept mixed alphanumeric with dots and hyphens", "my-placement.example-org.io", true),
			Entry("should accept names up to 253 characters", strings.Repeat("a", 253), true),

			// Invalid cases
			Entry("should reject names with uppercase characters", "MyPlacement", false),
			Entry("should reject names with underscores", "my_placement", false),
			Entry("should reject names starting with hyphen", "-invalid", false),
			Entry("should reject names ending with hyphen", "invalid-", false),
			Entry("should reject names starting with dot", ".invalid", false),
			Entry("should reject names ending with dot", "invalid.", false),
			Entry("should reject names with special characters", "placement@test", false),
			Entry("should reject names with spaces", "my placement", false),
			Entry("should reject empty names", "", false),
			Entry("should reject names with consecutive dots", "example..com", false),
			Entry("should reject names with hyphen after dot", "example.-com", false),
			Entry("should reject names with slashes", "example.com/my-placement", false),
			Entry("should reject names exceeding 253 characters", strings.Repeat("a", 254), false),
		)
	})

	Context("spec.roleAssignments[].clusterSelection.placements[].namespace validation", func() {
		DescribeTable("validation cases",
			func(placementNamespace string, shouldSucceed bool) {
				yamlPath := createTestMRAWithPlacementNamespace(placementNamespace)
				defer func() { _ = os.Remove(yamlPath) }()

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},
			// Valid cases
			Entry("should accept lowercase alphanumeric names", "default", true),
			Entry("should accept names with hyphens", "my-namespace", true),
			Entry("should accept names with numbers", "namespace-123", true),
			Entry("should accept single character names", "a", true),
			Entry("should accept all numbers", "123456", true),
			Entry("should accept single number names", "1", true),
			Entry("should accept numbers at start and end", "1ns2", true),
			Entry("should accept mixed alphanumeric with hyphens", "my-app-namespace-1", true),
			Entry("should accept names up to 63 characters", strings.Repeat("a", 63), true),

			// Invalid cases
			Entry("should reject names with uppercase characters", "MyNamespace", false),
			Entry("should reject names with underscores", "my_namespace", false),
			Entry("should reject names with dots", "my.namespace", false),
			Entry("should reject names starting with hyphen", "-invalid", false),
			Entry("should reject names ending with hyphen", "invalid-", false),
			Entry("should reject names with special characters", "namespace@test", false),
			Entry("should reject names with spaces", "my namespace", false),
			Entry("should reject empty names", "", false),
			Entry("should reject names exceeding 63 characters", strings.Repeat("a", 64), false),
		)
	})

	Context("spec.subject validation", func() {
		DescribeTable("validation cases",
			func(apiGroup, kind, name, namespace string, shouldSucceed bool) {
				yamlPath := createTestMRAWithSubject(apiGroup, kind, name, namespace)
				defer func() { _ = os.Remove(yamlPath) }()

				if shouldSucceed {
					expectMRAApplyToSucceed(yamlPath)
				} else {
					expectMRAApplyToFail(yamlPath)
				}
			},

			// User Kind
			// Valid cases
			Entry("should accept User with empty apiGroup",
				noAPIGroup, userKind, "test-user", noNamespace, true),
			Entry("should accept User with rbac.authorization.k8s.io apiGroup",
				rbacAPIGroup, userKind, "test-user", noNamespace, true),
			Entry("should accept email-style user names",
				rbacAPIGroup, userKind, "admin@example.com", noNamespace, true),

			// Invalid cases
			Entry("should reject User with invalid.group apiGroup",
				"invalid.group", userKind, "test-user", noNamespace, false),
			Entry("should reject lowercase user kind",
				noAPIGroup, "user", "test-user", noNamespace, false),
			Entry("should reject User with non-empty namespace",
				noAPIGroup, userKind, "test-user", "default", false),
			Entry("should reject empty string User name",
				noAPIGroup, userKind, "", noNamespace, false),

			// Group Kind
			// Valid cases
			Entry("should accept Group with empty apiGroup",
				noAPIGroup, groupKind, "test-group", noNamespace, true),
			Entry("should accept Group with rbac.authorization.k8s.io apiGroup",
				rbacAPIGroup, groupKind, "test-group", noNamespace, true),
			Entry("should accept uppercase characters in Group names",
				noAPIGroup, groupKind, "TestGroup", noNamespace, true),

			// Invalid cases
			Entry("should reject Group with authorization.k8s.io apiGroup",
				"authorization.k8s.io", groupKind, "test-group", noNamespace, false),
			Entry("should reject lowercase group kind",
				noAPIGroup, "group", "test-group", noNamespace, false),
			Entry("should reject Group with non-empty namespace",
				noAPIGroup, groupKind, "test-group", "default", false),

			// ServiceAccount Kind
			// Valid cases
			Entry("should accept ServiceAccount with empty apiGroup",
				noAPIGroup, serviceAccountKind, "test-sa", "test-ns", true),
			Entry("should accept the default ServiceAccount",
				noAPIGroup, serviceAccountKind, "default", "default", true),
			Entry("should accept ServiceAccount with single character namespace",
				noAPIGroup, serviceAccountKind, "test-sa", "a", true),
			Entry("should accept ServiceAccount with hyphenated namespace",
				noAPIGroup, serviceAccountKind, "test-sa", "my-namespace", true),

			// Invalid cases
			Entry("should reject ServiceAccount with non-empty apiGroup",
				rbacAPIGroup, serviceAccountKind, "test-sa", "default", false),
			Entry("should reject ServiceAccount with empty namespace",
				noAPIGroup, serviceAccountKind, "test-sa", noNamespace, false),
			Entry("should reject ServiceAccount namespace with dots",
				noAPIGroup, serviceAccountKind, "test-sa", "my.namespace", false),
			Entry("should reject ServiceAccount namespace with uppercase",
				noAPIGroup, serviceAccountKind, "test-sa", "MyNamespace", false),
			Entry("should reject ServiceAccount namespace starting with hyphen",
				noAPIGroup, serviceAccountKind, "test-sa", "-invalid", false),
			Entry("should reject ServiceAccount namespace ending with hyphen",
				noAPIGroup, serviceAccountKind, "test-sa", "invalid-", false),
			Entry("should reject ServiceAccount namespace with special characters",
				noAPIGroup, serviceAccountKind, "test-sa", "namespace@test", false),
			Entry("should reject ServiceAccount namespace exceeding 63 characters",
				noAPIGroup, serviceAccountKind, "test-sa", strings.Repeat("a", 64), false),

			// Other
			// Invalid cases
			Entry("should reject empty kind",
				noAPIGroup, "", "test-name", noNamespace, false),
			Entry("should reject random kind",
				noAPIGroup, "RandomKind", "test-name", noNamespace, false),
		)
	})
})

// buildMRAYAML creates a temporary MRA YAML file with customizable field values. Nil pointers use default values.
func buildMRAYAML(
	clusterRole, placementName, placementNamespace, subjectAPIGroup, subjectKind, subjectName, subjectNamespace *string,
	targetNamespaces []string) string {

	setClusterRole := "test-role"
	if clusterRole != nil {
		setClusterRole = *clusterRole
	}

	setPlacementName := "test-placement"
	if placementName != nil {
		setPlacementName = *placementName
	}

	setPlacementNamespace := "test-placement-ns"
	if placementNamespace != nil {
		setPlacementNamespace = *placementNamespace
	}

	setSubjectApiGroup := ""
	if subjectAPIGroup != nil {
		setSubjectApiGroup = *subjectAPIGroup
	}

	setSubjectKind := "User"
	if subjectKind != nil {
		setSubjectKind = *subjectKind
	}

	setSubjectName := "test-user"
	if subjectName != nil {
		setSubjectName = *subjectName
	}

	setSubjectNamespace := ""
	if subjectNamespace != nil {
		setSubjectNamespace = *subjectNamespace
	}

	targetNamespacesSection := ""
	if len(targetNamespaces) > 0 {
		targetNamespacesSection = "\n      targetNamespaces:"
		for _, ns := range targetNamespaces {
			targetNamespacesSection += fmt.Sprintf("\n        - \"%s\"", ns)
		}
	}

	subjectAPIGroupSection := ""
	if setSubjectApiGroup != "" {
		subjectAPIGroupSection = fmt.Sprintf("\n    apiGroup: \"%s\"", setSubjectApiGroup)
	}

	subjectNamespaceSection := ""
	if setSubjectNamespace != "" {
		subjectNamespaceSection = fmt.Sprintf("\n    namespace: \"%s\"", setSubjectNamespace)
	}

	content := fmt.Sprintf(`apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: crd-validation-test
  namespace: default
spec:
  subject:%s
    kind: "%s"
    name: "%s"%s
  roleAssignments:
    - name: test-assignment
      clusterRole: "%s"%s
      clusterSelection:
        type: placements
        placements:
          - name: "%s"
            namespace: "%s"
`, subjectAPIGroupSection, setSubjectKind, setSubjectName, subjectNamespaceSection, setClusterRole,
		targetNamespacesSection, setPlacementName, setPlacementNamespace)

	tmpFile, err := os.CreateTemp("", "mra-validation-*.yaml")
	Expect(err).NotTo(HaveOccurred())

	_, err = tmpFile.WriteString(content)
	Expect(err).NotTo(HaveOccurred())

	err = tmpFile.Close()
	Expect(err).NotTo(HaveOccurred())

	return tmpFile.Name()
}

// createTestMRAWithClusterRole creates a test MRA with a specific clusterRole value.
func createTestMRAWithClusterRole(clusterRoleName string) string {
	return buildMRAYAML(&clusterRoleName, nil, nil, nil, nil, nil, nil, nil)
}

// createTestMRAWithTargetNamespace creates a test MRA with specific targetNamespaces values.
func createTestMRAWithTargetNamespace(targetNamespaces ...string) string {
	return buildMRAYAML(nil, nil, nil, nil, nil, nil, nil, targetNamespaces)
}

// createTestMRAWithPlacementName creates a test MRA with a specific placement name.
func createTestMRAWithPlacementName(placementName string) string {
	return buildMRAYAML(nil, &placementName, nil, nil, nil, nil, nil, nil)
}

// createTestMRAWithPlacementNamespace creates a test MRA with a specific placement namespace.
func createTestMRAWithPlacementNamespace(placementNamespace string) string {
	return buildMRAYAML(nil, nil, &placementNamespace, nil, nil, nil, nil, nil)
}

// createTestMRAWithSubject creates a test MRA with specific subject field values.
func createTestMRAWithSubject(apiGroup, kind, name, namespace string) string {
	return buildMRAYAML(nil, nil, nil, &apiGroup, &kind, &name, &namespace, nil)
}

// expectMRAApplyToFail applies MRA YAML via kubectl and expects it to fail with a validation error.
func expectMRAApplyToFail(yamlPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", yamlPath)
	output, err := utils.Run(cmd)
	Expect(err).To(HaveOccurred())
	Expect(output).To(ContainSubstring("Invalid value"))
}

// expectMRAApplyToSucceed applies MRA YAML via kubectl and expects it to succeed.
func expectMRAApplyToSucceed(yamlPath string) {
	cmd := exec.Command("kubectl", "apply", "-f", yamlPath)
	_, err := utils.Run(cmd)
	Expect(err).NotTo(HaveOccurred())
}

// cleanupCRDValidationTestMRA deletes the test MulticlusterRoleAssignment if it exists.
func cleanupCRDValidationTestMRA() {
	cmd := exec.Command(
		"kubectl", "delete", "multiclusterroleassignment", "-n", "default", "crd-validation-test",
		"--ignore-not-found=true")
	_, _ = utils.Run(cmd)
}
