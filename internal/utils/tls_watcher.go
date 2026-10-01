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

	configv1 "github.com/openshift/api/config/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

// HubAPIServerTLSProfileWatcher watches the cluster-scoped OpenShift APIServer resource and
// invokes onProfileChange when the resolved TLSSecurityProfile differs from appliedProfile.
// Metrics server TLS options are fixed at startup, so the typical response is to cancel the
// manager context and let the pod restart with the updated profile.
type HubAPIServerTLSProfileWatcher struct {
	client.Client

	appliedProfile  configv1.TLSProfileSpec
	onProfileChange func(context.Context, configv1.TLSProfileSpec, configv1.TLSProfileSpec)
}

// SetupHubAPIServerTLSProfileWatcher registers a watch on APIServer resources named "cluster".
func SetupHubAPIServerTLSProfileWatcher(
	mgr ctrl.Manager,
	appliedProfile configv1.TLSProfileSpec,
	onProfileChange func(context.Context, configv1.TLSProfileSpec, configv1.TLSProfileSpec),
) error {
	watcher := &HubAPIServerTLSProfileWatcher{
		Client:          mgr.GetClient(),
		appliedProfile:  appliedProfile,
		onProfileChange: onProfileChange,
	}

	clusterAPIServerPredicate := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return isHubAPIServer(e.Object)
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return isHubAPIServer(e.ObjectNew)
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			return isHubAPIServer(e.Object)
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return isHubAPIServer(e.Object)
		},
	}

	return builder.ControllerManagedBy(mgr).
		For(&configv1.APIServer{}).
		WithEventFilter(clusterAPIServerPredicate).
		WithOptions(controller.Options{NeedLeaderElection: ptr.To(false)}).
		Complete(watcher)
}

func isHubAPIServer(obj client.Object) bool {
	return obj != nil && obj.GetName() == hubAPIServerName
}

// Reconcile compares the hub APIServer's resolved TLS profile with the profile applied at startup.
func (w *HubAPIServerTLSProfileWatcher) Reconcile(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
	if req.Name != hubAPIServerName {
		return reconcile.Result{}, nil
	}

	logger := log.FromContext(ctx)

	apiServer := &configv1.APIServer{}
	var current *configv1.TLSProfileSpec

	if err := w.Get(ctx, types.NamespacedName{Name: hubAPIServerName}, apiServer); err != nil {
		if apierrors.IsNotFound(err) {
			current = DefaultTLSSecurityProfile()
		} else {
			return reconcile.Result{}, err
		}
	} else {
		current = ResolveTLSSecurityProfile(apiServer)
	}
	if TLSSecurityProfileSpecsEqual(&w.appliedProfile, current) {
		return reconcile.Result{}, nil
	}

	logger.Info("hub TLSSecurityProfile changed, requesting restart to apply new metrics server TLS settings",
		"oldMinTLSVersion", w.appliedProfile.MinTLSVersion,
		"newMinTLSVersion", current.MinTLSVersion,
		"oldGroups", w.appliedProfile.Groups,
		"newGroups", current.Groups)

	if w.onProfileChange != nil {
		w.onProfileChange(ctx, w.appliedProfile, *current)
	}

	return reconcile.Result{}, nil
}

// CopyTLSSecurityProfileSpec returns a deep copy of spec suitable for comparisons and storage.
func CopyTLSSecurityProfileSpec(spec *configv1.TLSProfileSpec) configv1.TLSProfileSpec {
	if spec == nil {
		return *DefaultTLSSecurityProfile()
	}

	return configv1.TLSProfileSpec{
		MinTLSVersion: spec.MinTLSVersion,
		Ciphers:       append([]string(nil), spec.Ciphers...),
		Groups:        append([]configv1.TLSGroup(nil), spec.Groups...),
	}
}

// TLSSecurityProfileSpecsEqual reports whether two profile specs affect metrics server TLS the same way.
func TLSSecurityProfileSpecsEqual(a, b *configv1.TLSProfileSpec) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	return equality.Semantic.DeepEqual(*a, *b)
}
