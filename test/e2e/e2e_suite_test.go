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
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/stolostron/multicluster-role-assignment/test/utils"
)

var (
	// projectImage is the name of the image which will be build and loaded
	// with the code source changes to be tested.
	projectImage = "example.com/multicluster-role-assignment:v0.0.1"

	// afterSuiteCleanupTimeout bounds AfterSuite teardown so the go test deadline is not consumed
	// by kubectl waiting on finalizers (make undeploy has hung in CI for several minutes).
	afterSuiteCleanupTimeout = 90 * time.Second
)

// TestE2E runs the end-to-end (e2e) test suite for the project. These tests execute in an isolated,
// temporary environment to validate project changes with the purpose of being used in CI jobs.
// The default setup requires Kind and builds/loads the Manager Docker image locally.
func TestE2E(t *testing.T) {
	RegisterFailHandler(Fail)
	_, _ = fmt.Fprintf(GinkgoWriter, "Starting multicluster-role-assignment integration test suite\n")
	RunSpecs(t, "e2e suite")
}

var _ = BeforeSuite(func() {
	By("building the manager(Operator) image")
	cmd := exec.Command("make", "docker-build", fmt.Sprintf("IMG=%s", projectImage))
	_, err := utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to build the manager(Operator) image")

	// TODO(user): If you want to change the e2e test vendor from Kind, ensure the image is
	// built and available before running the tests. Also, remove the following block.
	By("loading the manager(Operator) image on Kind")
	err = utils.LoadImageToKindClusterWithName(projectImage)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to load the manager(Operator) image into Kind")

	By("installing CRDs")
	cmd = exec.Command("make", "install")
	_, err = utils.Run(cmd)
	ExpectWithOffset(1, err).NotTo(HaveOccurred(), "Failed to install CRDs")
})

// runBoundedCleanup runs a kubectl (or other) command with a hard timeout. Errors are logged and ignored.
func runBoundedCleanup(description string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), afterSuiteCleanupTimeout)
	defer cancel()

	By(description)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if _, err := utils.Run(cmd); err != nil {
		_, _ = fmt.Fprintf(GinkgoWriter, "AfterSuite cleanup (%s): %v\n", description, err)
	}
}

var _ = AfterSuite(func() {
	// Do not run `make undeploy`: piping kustomize into `kubectl delete -f` can block until
	// namespace finalizers clear and exhaust the default 10m go test timeout in CI.
	runBoundedCleanup(
		"deleting controller-manager deployment (best effort)",
		"kubectl", "delete", "deployment", "controller-manager",
		"-n", namespace, "--ignore-not-found", "--wait=false",
	)
	runBoundedCleanup(
		"deleting manager namespace (best effort)",
		"kubectl", "delete", "namespace", namespace,
		"--ignore-not-found", "--wait=false", "--grace-period=0",
	)
})
