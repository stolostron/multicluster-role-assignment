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
	"crypto/tls"
	"errors"
	"testing"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newSchemeWithConfigV1(t *testing.T) *runtime.Scheme {
	t.Helper()

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("failed to add client-go scheme: %v", err)
	}

	if err := configv1.Install(scheme); err != nil {
		t.Fatalf("failed to add configv1 scheme: %v", err)
	}

	return scheme
}

func TestGetHubTLSSecurityProfile(t *testing.T) {
	intermediate := configv1.TLSProfiles[configv1.TLSProfileIntermediateType]

	tests := []struct {
		name      string
		apiServer *configv1.APIServer
		expected  *configv1.TLSProfileSpec
	}{
		{
			name:      "no APIServer resource (non-OpenShift hub) falls back to Intermediate",
			apiServer: nil,
			expected:  intermediate,
		},
		{
			name: "APIServer exists but no TLSSecurityProfile set falls back to Intermediate",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
			},
			expected: intermediate,
		},
		{
			name: "predefined Old profile resolves from the well-known map",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileOldType,
					},
				},
			},
			expected: configv1.TLSProfiles[configv1.TLSProfileOldType],
		},
		{
			name: "predefined Modern profile resolves from the well-known map",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileModernType,
					},
				},
			},
			expected: configv1.TLSProfiles[configv1.TLSProfileModernType],
		},
		{
			name: "custom profile returns the inline spec, including groups",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
						Custom: &configv1.CustomTLSProfile{
							TLSProfileSpec: configv1.TLSProfileSpec{
								MinTLSVersion: configv1.VersionTLS12,
								Ciphers:       []string{opensslCipherECDHERSAAES128GCM},
								Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
							},
						},
					},
				},
			},
			expected: &configv1.TLSProfileSpec{
				MinTLSVersion: configv1.VersionTLS12,
				Ciphers:       []string{opensslCipherECDHERSAAES128GCM},
				Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
			},
		},
		{
			name: "custom profile without inline spec falls back to Intermediate",
			apiServer: &configv1.APIServer{
				ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
				Spec: configv1.APIServerSpec{
					TLSSecurityProfile: &configv1.TLSSecurityProfile{
						Type: configv1.TLSProfileCustomType,
					},
				},
			},
			expected: intermediate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newSchemeWithConfigV1(t)

			var objs []ctrlclient.Object
			if tt.apiServer != nil {
				objs = append(objs, tt.apiServer)
			}

			cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()

			got, err := GetHubTLSSecurityProfile(context.Background(), cl)
			if err != nil {
				t.Fatalf("GetHubTLSSecurityProfile() unexpected error: %v", err)
			}

			if got.MinTLSVersion != tt.expected.MinTLSVersion {
				t.Errorf("MinTLSVersion = %v, expected %v", got.MinTLSVersion, tt.expected.MinTLSVersion)
			}

			if len(got.Ciphers) != len(tt.expected.Ciphers) {
				t.Errorf("Ciphers = %v, expected %v", got.Ciphers, tt.expected.Ciphers)
			}

			if len(got.Groups) != len(tt.expected.Groups) {
				t.Errorf("Groups = %v, expected %v", got.Groups, tt.expected.Groups)
			}
		})
	}
}

type denyAPIServerGetClient struct {
	ctrlclient.Client
}

func (d *denyAPIServerGetClient) Get(
	_ context.Context,
	key types.NamespacedName,
	_ ctrlclient.Object,
	_ ...ctrlclient.GetOption,
) error {
	if key.Name == hubAPIServerName {
		return apierrors.NewForbidden(configv1.Resource("apiservers"), key.Name, errors.New("denied"))
	}

	return d.Client.Get(context.Background(), key, nil)
}

func TestGetHubTLSSecurityProfile_forbiddenReturnsError(t *testing.T) {
	scheme := newSchemeWithConfigV1(t)
	base := fake.NewClientBuilder().WithScheme(scheme).Build()
	cl := &denyAPIServerGetClient{Client: base}

	_, err := GetHubTLSSecurityProfile(context.Background(), cl)
	if err == nil {
		t.Fatal("expected error when APIServer get is forbidden")
	}
}

type flakyAPIServerGetClient struct {
	ctrlclient.Client

	apiServer *configv1.APIServer
	attempts  int
}

func (f *flakyAPIServerGetClient) Get(
	ctx context.Context,
	key types.NamespacedName,
	obj ctrlclient.Object,
	opts ...ctrlclient.GetOption,
) error {
	if key.Name != hubAPIServerName {
		return f.Client.Get(ctx, key, obj, opts...)
	}

	f.attempts++
	if f.attempts == 1 {
		return apierrors.NewServiceUnavailable("temporary")
	}

	apiServer, ok := obj.(*configv1.APIServer)
	if !ok {
		return errors.New("unexpected object type")
	}

	f.apiServer.DeepCopyInto(apiServer)
	return nil
}

func TestGetHubTLSSecurityProfileWithRetry_succeedsAfterTransientFailure(t *testing.T) {
	scheme := newSchemeWithConfigV1(t)
	apiServer := &configv1.APIServer{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster"},
		Spec: configv1.APIServerSpec{
			TLSSecurityProfile: &configv1.TLSSecurityProfile{
				Type: configv1.TLSProfileModernType,
			},
		},
	}

	base := fake.NewClientBuilder().WithScheme(scheme).WithObjects(apiServer).Build()
	cl := &flakyAPIServerGetClient{Client: base, apiServer: apiServer}

	origBackoff := hubTLSProfileReadBackoff
	hubTLSProfileReadBackoff = wait.Backoff{Duration: time.Millisecond, Factor: 1, Steps: 3}
	defer func() { hubTLSProfileReadBackoff = origBackoff }()

	got, err := GetHubTLSSecurityProfileWithRetry(context.Background(), cl)
	if err != nil {
		t.Fatalf("GetHubTLSSecurityProfileWithRetry() error: %v", err)
	}

	if got.MinTLSVersion != configv1.VersionTLS13 {
		t.Fatalf("expected Modern profile TLS 1.3, got %v", got.MinTLSVersion)
	}

	if cl.attempts < 2 {
		t.Fatalf("expected at least two get attempts, got %d", cl.attempts)
	}
}

func TestConvertTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  configv1.TLSProtocolVersion
		expected uint16
	}{
		{"TLS 1.0", configv1.VersionTLS10, tls.VersionTLS10},
		{"TLS 1.1", configv1.VersionTLS11, tls.VersionTLS11},
		{"TLS 1.2", configv1.VersionTLS12, tls.VersionTLS12},
		{"TLS 1.3", configv1.VersionTLS13, tls.VersionTLS13},
		{"unrecognized defaults to TLS 1.2", configv1.TLSProtocolVersion("bogus"), tls.VersionTLS12},
		{"empty defaults to TLS 1.2", configv1.TLSProtocolVersion(""), tls.VersionTLS12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConvertTLSVersion(tt.version); got != tt.expected {
				t.Errorf("ConvertTLSVersion(%v) = %v, expected %v", tt.version, got, tt.expected)
			}
		})
	}
}

func TestConvertCipherSuites(t *testing.T) {
	tests := []struct {
		name     string
		ciphers  []string
		expected []uint16
	}{
		{
			name:     "known OpenSSL cipher names convert to crypto/tls constants",
			ciphers:  []string{opensslCipherECDHERSAAES128GCM, "AES128-SHA"},
			expected: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA},
		},
		{
			name:     "TLS 1.3 cipher names are not configurable and are skipped",
			ciphers:  []string{"TLS_AES_128_GCM_SHA256"},
			expected: []uint16{},
		},
		{
			name:     "unknown cipher names are skipped",
			ciphers:  []string{"not-a-real-cipher"},
			expected: []uint16{},
		},
		{
			name:     "empty input returns empty output",
			ciphers:  nil,
			expected: []uint16{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertCipherSuites(tt.ciphers)
			if len(got) != len(tt.expected) {
				t.Fatalf("ConvertCipherSuites(%v) = %v, expected %v", tt.ciphers, got, tt.expected)
			}

			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("ConvertCipherSuites(%v)[%d] = %v, expected %v", tt.ciphers, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestConvertGroups(t *testing.T) {
	tests := []struct {
		name     string
		groups   []configv1.TLSGroup
		expected []tls.CurveID
	}{
		{
			name:     "known groups convert to crypto/tls CurveIDs",
			groups:   []configv1.TLSGroup{configv1.TLSGroupX25519, configv1.TLSGroupSecP256r1},
			expected: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		{
			name:     "post-quantum hybrid groups convert to crypto/tls CurveIDs",
			groups:   []configv1.TLSGroup{configv1.TLSGroupX25519MLKEM768},
			expected: []tls.CurveID{tls.X25519MLKEM768},
		},
		{
			name:     "unknown groups are skipped",
			groups:   []configv1.TLSGroup{"not-a-real-group"},
			expected: []tls.CurveID{},
		},
		{
			name:     "empty input returns empty output",
			groups:   nil,
			expected: []tls.CurveID{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertGroups(tt.groups)
			if len(got) != len(tt.expected) {
				t.Fatalf("ConvertGroups(%v) = %v, expected %v", tt.groups, got, tt.expected)
			}

			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("ConvertGroups(%v)[%d] = %v, expected %v", tt.groups, i, got[i], tt.expected[i])
				}
			}
		})
	}
}

func TestApplyTLSSecurityProfile(t *testing.T) {
	t.Run("TLS 1.2 profile applies MinVersion, CipherSuites, and CurvePreferences", func(t *testing.T) {
		profile := &configv1.TLSProfileSpec{
			MinTLSVersion: configv1.VersionTLS12,
			Ciphers:       []string{opensslCipherECDHERSAAES128GCM},
			Groups:        []configv1.TLSGroup{configv1.TLSGroupX25519},
		}

		cfg := &tls.Config{}
		ApplyTLSSecurityProfile(profile)(cfg)

		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %v, expected %v", cfg.MinVersion, tls.VersionTLS12)
		}

		if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 {
			t.Errorf("CipherSuites = %v, expected [%v]", cfg.CipherSuites, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
		}

		if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.X25519 {
			t.Errorf("CurvePreferences = %v, expected [%v]", cfg.CurvePreferences, tls.X25519)
		}
	})

	t.Run("TLS 1.3 profile does not set CipherSuites since Go manages those automatically", func(t *testing.T) {
		profile := &configv1.TLSProfileSpec{
			MinTLSVersion: configv1.VersionTLS13,
			Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
			Groups:        []configv1.TLSGroup{configv1.TLSGroupSecP384r1},
		}

		cfg := &tls.Config{}
		ApplyTLSSecurityProfile(profile)(cfg)

		if cfg.MinVersion != tls.VersionTLS13 {
			t.Errorf("MinVersion = %v, expected %v", cfg.MinVersion, tls.VersionTLS13)
		}

		if cfg.CipherSuites != nil {
			t.Errorf("CipherSuites = %v, expected nil for TLS 1.3", cfg.CipherSuites)
		}

		if len(cfg.CurvePreferences) != 1 || cfg.CurvePreferences[0] != tls.CurveP384 {
			t.Errorf("CurvePreferences = %v, expected [%v]", cfg.CurvePreferences, tls.CurveP384)
		}
	})

	t.Run("TLS 1.2 profile with no convertible ciphers sets empty CipherSuites", func(t *testing.T) {
		profile := &configv1.TLSProfileSpec{
			MinTLSVersion: configv1.VersionTLS12,
			Ciphers:       []string{"TLS_AES_128_GCM_SHA256"},
		}

		cfg := &tls.Config{}
		ApplyTLSSecurityProfile(profile)(cfg)

		if cfg.CipherSuites == nil {
			t.Fatal("CipherSuites should be a non-nil empty slice to disable default TLS 1.2 suites")
		}

		if len(cfg.CipherSuites) != 0 {
			t.Fatalf("CipherSuites = %v, expected empty slice", cfg.CipherSuites)
		}
	})

	t.Run("profile without groups leaves CurvePreferences unset", func(t *testing.T) {
		profile := &configv1.TLSProfileSpec{
			MinTLSVersion: configv1.VersionTLS12,
		}

		cfg := &tls.Config{}
		ApplyTLSSecurityProfile(profile)(cfg)

		if cfg.CurvePreferences != nil {
			t.Errorf("CurvePreferences = %v, expected nil", cfg.CurvePreferences)
		}
	})
}
