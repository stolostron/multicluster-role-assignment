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

package utils

import (
	"context"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestHubAPIServerTLSProfileWatcher_ReconcileOnProfileChange(t *testing.T) {
	scheme := newSchemeWithConfigV1(t)

	applied := CopyTLSSecurityProfileSpec(configv1.TLSProfiles[configv1.TLSProfileIntermediateType])

	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: hubAPIServerName},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
		},
	}

	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()

	changed := false
	watcher := &HubAPIServerTLSProfileWatcher{
		Client:         cl,
		appliedProfile: applied,
		onProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			changed = true
		},
	}

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{NamespacedName: ctrlclient.ObjectKey{Name: hubAPIServerName}})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	if !changed {
		t.Fatal("expected onProfileChange to be called when hub profile changes")
	}
}

func TestHubAPIServerTLSProfileWatcher_ReconcileOnAPIServerDeletion(t *testing.T) {
	scheme := newSchemeWithConfigV1(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	applied := CopyTLSSecurityProfileSpec(configv1.TLSProfiles[configv1.TLSProfileModernType])

	changed := false
	watcher := &HubAPIServerTLSProfileWatcher{
		Client:         cl,
		appliedProfile: applied,
		onProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			changed = true
		},
	}

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{NamespacedName: ctrlclient.ObjectKey{Name: hubAPIServerName}})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	if !changed {
		t.Fatal("expected onProfileChange when APIServer is deleted and applied profile is not Intermediate")
	}
}

func TestHubAPIServerTLSProfileWatcher_ReconcileIgnoresUnrelatedAPIServer(t *testing.T) {
	scheme := newSchemeWithConfigV1(t)
	cl := fake.NewClientBuilder().WithScheme(scheme).Build()

	changed := false
	watcher := &HubAPIServerTLSProfileWatcher{
		Client:         cl,
		appliedProfile: CopyTLSSecurityProfileSpec(DefaultTLSSecurityProfile()),
		onProfileChange: func(_ context.Context, _, _ configv1.TLSProfileSpec) {
			changed = true
		},
	}

	_, err := watcher.Reconcile(context.Background(), reconcile.Request{NamespacedName: ctrlclient.ObjectKey{Name: "other"}})
	if err != nil {
		t.Fatalf("Reconcile() error: %v", err)
	}

	if changed {
		t.Fatal("expected onProfileChange not to run for unrelated APIServer names")
	}
}
