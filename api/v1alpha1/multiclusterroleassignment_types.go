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

package v1alpha1

import (
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// MulticlusterRoleAssignmentSpec defines the desired state of MulticlusterRoleAssignment.
type MulticlusterRoleAssignmentSpec struct {
	// Subject defines the user, group, or service account for all role assignments.
	// +kubebuilder:validation:Required
	Subject rbacv1.Subject `json:"subject"`

	// RoleAssignments defines the list of role assignments for different roles, namespaces, and cluster sets.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:ListType=map
	// +kubebuilder:validation:ListMapKey=name
	RoleAssignments []RoleAssignment `json:"roleAssignments"`
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
	// assignment. If TargetNamespaces is not present, the role will be applied to all clusters' namespaces.
	// +kubebuilder:validation:Optional
	TargetNamespaces []string `json:"targetNamespaces,omitempty"`

	// ClusterSelection defines the type of cluster selection and the clusters to be selected.
	// +kubebuilder:validation:Required
	ClusterSelection ClusterSelection `json:"clusterSelection"`
}

type ClusterSelection struct {
	// Type defines the type of cluster selection.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum={clusterNames}
	Type string `json:"type"`

	// ClusterNames defines the clusters where the role should be applied.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	ClusterNames []string `json:"clusterNames"`
}

// MulticlusterRoleAssignmentStatus defines the observed state of MulticlusterRoleAssignment.
type MulticlusterRoleAssignmentStatus struct {
	// Conditions is the condition list.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// RoleAssignments provides the status of each role assignment.
	// +optional
	RoleAssignments []RoleAssignmentStatus `json:"roleAssignments,omitempty"`
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
