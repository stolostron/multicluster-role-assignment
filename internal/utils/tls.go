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
	"fmt"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// hubAPIServerName is the name of the cluster-scoped OpenShift APIServer resource that carries the
// cluster-wide TLSSecurityProfile.
const hubAPIServerName = "cluster"

// DefaultTLSSecurityProfile is used whenever the hub's TLSSecurityProfile can't be determined, e.g.
// the hub isn't running OpenShift, or no TLSSecurityProfile is configured on the APIServer resource.
func DefaultTLSSecurityProfile() *configv1.TLSProfileSpec {
	return configv1.TLSProfiles[configv1.TLSProfileIntermediateType]
}

// GetHubTLSSecurityProfile resolves the TLSSecurityProfile configured on the hub cluster's OpenShift
// APIServer resource (config.openshift.io/v1, name "cluster"). On non-OpenShift hubs (or any hub where
// the APIServer resource/CRD can't be found) it returns the DefaultTLSSecurityProfile instead of an
// error, since there is nothing cluster-level to honor in that case.
// hubTLSProfileReadBackoff is used when reading the hub APIServer TLS profile at startup.
var hubTLSProfileReadBackoff = wait.Backoff{
	Duration: time.Second,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    5,
	Cap:      30 * time.Second,
}

// GetHubTLSSecurityProfile resolves the hub TLSSecurityProfile from the APIServer resource. Transient
// or permission errors are returned to the caller; only a missing APIServer CRD/resource uses the default.
func GetHubTLSSecurityProfile(ctx context.Context, cl client.Client) (*configv1.TLSProfileSpec, error) {
	apiServer := &configv1.APIServer{}

	err := cl.Get(ctx, types.NamespacedName{Name: hubAPIServerName}, apiServer)
	if err != nil {
		// Non-OpenShift hubs don't have the APIServer CRD/resource installed at all, so there is no
		// cluster-wide TLSSecurityProfile to honor. Fall back to the default rather than failing.
		if apierrors.IsNotFound(err) || meta.IsNoMatchError(err) {
			return DefaultTLSSecurityProfile(), nil
		}

		return nil, fmt.Errorf("failed to get hub APIServer resource %q: %w", hubAPIServerName, err)
	}

	return ResolveTLSSecurityProfile(apiServer), nil
}

// GetHubTLSSecurityProfileWithRetry reads the hub profile with exponential backoff. Use at startup
// when a misconfigured RBAC or temporary API failure must not silently fall back to Intermediate.
func GetHubTLSSecurityProfileWithRetry(ctx context.Context, cl client.Client) (*configv1.TLSProfileSpec, error) {
	var profile *configv1.TLSProfileSpec

	err := wait.ExponentialBackoffWithContext(ctx, hubTLSProfileReadBackoff, func(ctx context.Context) (bool, error) {
		p, err := GetHubTLSSecurityProfile(ctx, cl)
		if err != nil {
			return false, nil
		}

		profile = p
		return true, nil
	})
	if err != nil {
		return nil, fmt.Errorf("timed out reading hub APIServer TLS profile: %w", err)
	}

	if profile == nil {
		return nil, fmt.Errorf("hub APIServer TLS profile read succeeded but returned no profile")
	}

	return profile, nil
}

// ResolveTLSSecurityProfile returns the effective TLSProfileSpec from an APIServer object.
func ResolveTLSSecurityProfile(apiServer *configv1.APIServer) *configv1.TLSProfileSpec {
	if apiServer == nil {
		return DefaultTLSSecurityProfile()
	}

	profile := apiServer.Spec.TLSSecurityProfile
	if profile == nil {
		return DefaultTLSSecurityProfile()
	}

	// Predefined profiles (Old, Intermediate, Modern) are looked up from the well-known map.
	if profileSpec, ok := configv1.TLSProfiles[profile.Type]; ok {
		return profileSpec
	}

	// Custom profiles carry their own inline spec.
	if profile.Type == configv1.TLSProfileCustomType && profile.Custom != nil {
		return &profile.Custom.TLSProfileSpec
	}

	return DefaultTLSSecurityProfile()
}

// tlsVersionByProfileVersion maps OpenShift's TLSProtocolVersion to crypto/tls's numeric version constants.
var tlsVersionByProfileVersion = map[configv1.TLSProtocolVersion]uint16{
	configv1.VersionTLS10: tls.VersionTLS10,
	configv1.VersionTLS11: tls.VersionTLS11,
	configv1.VersionTLS12: tls.VersionTLS12,
	configv1.VersionTLS13: tls.VersionTLS13,
}

// ConvertTLSVersion converts an OpenShift TLSProtocolVersion into the matching crypto/tls numeric
// version constant, defaulting to TLS 1.2 for unrecognized or empty values.
func ConvertTLSVersion(version configv1.TLSProtocolVersion) uint16 {
	if v, ok := tlsVersionByProfileVersion[version]; ok {
		return v
	}

	return tls.VersionTLS12
}

// cipherSuiteByOpenSSLName maps OpenShift's OpenSSL-formatted cipher suite names to crypto/tls's
// numeric cipher suite constants. Only ciphers supported by Go's crypto/tls package are included;
// TLS 1.3 cipher suites are not configurable in Go and are intentionally omitted.
const (
	opensslCipherECDHEECDSAAES128GCM = "ECDHE-ECDSA-AES128-GCM-SHA256"
	opensslCipherECDHERSAAES128GCM   = "ECDHE-RSA-AES128-GCM-SHA256"
	opensslCipherECDHEECDSAAES256GCM = "ECDHE-ECDSA-AES256-GCM-SHA384"
	opensslCipherECDHERSAAES256GCM   = "ECDHE-RSA-AES256-GCM-SHA384"
	opensslCipherECDHEECDSAChaCha    = "ECDHE-ECDSA-CHACHA20-POLY1305"
	opensslCipherECDHERSAChaCha      = "ECDHE-RSA-CHACHA20-POLY1305"
)

var cipherSuiteByOpenSSLName = map[string]uint16{
	opensslCipherECDHEECDSAAES128GCM: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	opensslCipherECDHERSAAES128GCM:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	opensslCipherECDHEECDSAAES256GCM: tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	opensslCipherECDHERSAAES256GCM:   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	opensslCipherECDHEECDSAChaCha:    tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	opensslCipherECDHERSAChaCha:      tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	"ECDHE-ECDSA-AES128-SHA256":      tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-RSA-AES128-SHA256":        tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	"ECDHE-ECDSA-AES128-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
	"ECDHE-RSA-AES128-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	"ECDHE-ECDSA-AES256-SHA":         tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	"ECDHE-RSA-AES256-SHA":           tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	"AES128-GCM-SHA256":              tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	"AES256-GCM-SHA384":              tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
	"AES128-SHA256":                  tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	"AES128-SHA":                     tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	"AES256-SHA":                     tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	"DES-CBC3-SHA":                   tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, //nolint:staticcheck // allow legacy cipher mapping
}

// ConvertCipherSuites converts OpenShift's OpenSSL-formatted cipher suite names into crypto/tls's
// numeric cipher suite constants. Names that Go's crypto/tls package doesn't support (e.g. TLS 1.3
// cipher suites, which Go manages automatically) are silently skipped.
func ConvertCipherSuites(names []string) []uint16 {
	suites := make([]uint16, 0, len(names))

	for _, name := range names {
		if suite, ok := cipherSuiteByOpenSSLName[name]; ok {
			suites = append(suites, suite)
		}
	}

	return suites
}

// curveIDByTLSGroup maps OpenShift's TLSGroup values (supported key-exchange groups, formerly known as
// elliptic curves) to crypto/tls's CurveID constants.
var curveIDByTLSGroup = map[configv1.TLSGroup]tls.CurveID{
	configv1.TLSGroupX25519:             tls.X25519,
	configv1.TLSGroupSecP256r1:          tls.CurveP256,
	configv1.TLSGroupSecP384r1:          tls.CurveP384,
	configv1.TLSGroupSecP521r1:          tls.CurveP521,
	configv1.TLSGroupX25519MLKEM768:     tls.X25519MLKEM768,
	configv1.TLSGroupSecP256r1MLKEM768:  tls.SecP256r1MLKEM768,
	configv1.TLSGroupSecP384r1MLKEM1024: tls.SecP384r1MLKEM1024,
}

// ConvertGroups converts OpenShift's TLSGroup values into crypto/tls's CurveID constants, for use as
// tls.Config.CurvePreferences. Groups that Go's crypto/tls package doesn't recognize are silently
// skipped, since the profile may list groups meant for other (non-Go) components.
func ConvertGroups(groups []configv1.TLSGroup) []tls.CurveID {
	curves := make([]tls.CurveID, 0, len(groups))

	for _, group := range groups {
		if curve, ok := curveIDByTLSGroup[group]; ok {
			curves = append(curves, curve)
		}
	}

	return curves
}

// ApplyTLSSecurityProfile returns a tls.Config mutator that applies the given TLSProfileSpec's
// minimum TLS version, cipher suites, and supported groups (CurvePreferences). It's intended to be
// used as one of controller-runtime's TLSOpts for a TLS-terminating server (e.g. the metrics server).
func ApplyTLSSecurityProfile(profile *configv1.TLSProfileSpec) func(*tls.Config) {
	minVersion := ConvertTLSVersion(profile.MinTLSVersion)
	cipherSuites := ConvertCipherSuites(profile.Ciphers)
	curvePreferences := ConvertGroups(profile.Groups)

	return func(c *tls.Config) {
		c.MinVersion = minVersion

		// TLS 1.3 cipher suites aren't configurable in Go and are always enabled when TLS 1.3 is
		// negotiated, so only apply the configured cipher suites when TLS 1.2 (or lower) may be used.
		if minVersion < tls.VersionTLS13 {
			c.CipherSuites = cipherSuites
		}

		if len(curvePreferences) > 0 {
			c.CurvePreferences = curvePreferences
		}
	}
}
