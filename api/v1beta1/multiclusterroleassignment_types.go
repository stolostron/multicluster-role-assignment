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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// MulticlusterRoleAssignmentSpec defines the desired state of MulticlusterRoleAssignment.
type MulticlusterRoleAssignmentSpec struct {
	// Subject defines the user, group, or service account for all role assignments.
	// +kubebuilder:validation:Required
	Subject Subject `json:"subject"`

	// RoleAssignments defines the list of role assignments for different roles, namespaces, and cluster sets.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	RoleAssignments []RoleAssignment `json:"roleAssignments"`
}

// Subject defines the user, group, or service account for role assignments.
// +kubebuilder:validation:XValidation:rule="!(self.kind in [\"User\", \"Group\"]) || !has(self.__namespace__)",message="Subject namespace must not be set for User and Group kinds"
// +kubebuilder:validation:XValidation:rule="self.kind != \"ServiceAccount\" || !has(self.apiGroup) || size(self.apiGroup) == 0",message="Subject apiGroup must be empty for ServiceAccount kind"
// +kubebuilder:validation:XValidation:rule="self.kind != \"ServiceAccount\" || (has(self.__namespace__) && size(self.__namespace__) > 0)",message="A namespace is required when subject kind is ServiceAccount"
type Subject struct {
	// API group of the referenced subject.
	// +kubebuilder:validation:Enum="";rbac.authorization.k8s.io
	// +optional
	APIGroup string `json:"apiGroup,omitempty"`

	// Kind of the subject. Accepted values are "User", "Group", and "ServiceAccount".
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=User;Group;ServiceAccount
	Kind string `json:"kind"`

	// Name of the subject.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the referenced subject. Must not be set for "User" or "Group" kinds. Must be set for "ServiceAccount"
	// kind. Must be a valid Kubernetes namespace name (DNS label).
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace,omitempty"`
}

// RoleAssignment defines a cluster role assignment to specific namespaces and clusters.
type RoleAssignment struct {
	// Name defines the name of the role assignment.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// ClusterRole defines the cluster role name to be assigned.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	ClusterRole string `json:"clusterRole"`

	// TargetNamespaces defines what namespaces the role should be applied in for all selected clusters in the role
	// assignment. If TargetNamespaces is not present, the role will be applied to all clusters' namespaces. Each
	// namespace must be a valid Kubernetes namespace name (DNS label).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:items:MinLength=1
	// +kubebuilder:validation:items:MaxLength=63
	// +kubebuilder:validation:items:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// ClusterSelection defines the type of cluster selection and the clusters to be selected.
	// +kubebuilder:validation:Required
	ClusterSelection ClusterSelection `json:"clusterSelection"`
}

// PlacementRef represents a reference to a Placement resource
type PlacementRef struct {
	// Name of the Placement resource. Must be a valid Kubernetes resource name (DNS subdomain).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	Name string `json:"name"`

	// Namespace of the Placement resource. Must be a valid Kubernetes namespace name (DNS label).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Namespace string `json:"namespace"`
}

type ClusterSelection struct {
	// Type defines the type of cluster selection.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum={placements}
	Type string `json:"type"`

	// Placements defines the Placement resources to use for cluster selection.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Placements []PlacementRef `json:"placements"`
}

// MulticlusterRoleAssignmentStatus defines the observed state of MulticlusterRoleAssignment.
type MulticlusterRoleAssignmentStatus struct {
	// Conditions is the condition list.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RoleAssignments provides the status of each role assignment.
	// +optional
	RoleAssignments []RoleAssignmentStatus `json:"roleAssignments,omitempty"`

	// AppliedClusters contains all (total) clusters where role assignments have been applied to.
	// +optional
	AppliedClusters []string `json:"appliedClusters,omitempty"`
}

// RoleAssignmentStatus defines the status of a specific role assignment.
type RoleAssignmentStatus struct {
	// Name defines the name of the role assignment.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// Status defines the current status of the role assignment.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=Pending;Active;Error
	Status string `json:"status"`

	// Reason provides a programmatic identifier for the role assignment status.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message provides additional human readable details about the role assignment status.
	// +optional
	Message string `json:"message,omitempty"`

	// CreatedAt defines the creation time of the roleAssignment.
	// +kubebuilder:validation:Required
	CreatedAt metav1.Time `json:"createdAt"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion

// MulticlusterRoleAssignment is the Schema for the multiclusterroleassignments API.
type MulticlusterRoleAssignment struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty,omitzero"`

	// spec defines the desired state of MulticlusterRoleAssignment
	// +required
	Spec MulticlusterRoleAssignmentSpec `json:"spec"`

	// status defines the observed state of MulticlusterRoleAssignment
	// +optional
	Status MulticlusterRoleAssignmentStatus `json:"status,omitempty,omitzero"`
}

// +kubebuilder:object:root=true

// MulticlusterRoleAssignmentList contains a list of MulticlusterRoleAssignment.
type MulticlusterRoleAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MulticlusterRoleAssignment `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MulticlusterRoleAssignment{}, &MulticlusterRoleAssignmentList{})
}
