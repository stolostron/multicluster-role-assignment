# ClusterPermission Design

This document explains the ClusterPermission management model for the MulticlusterRoleAssignment (MRA) controller.

## Overview

The MRA controller creates `ClusterPermission` resources to propagate RBAC bindings to managed clusters. Each ClusterPermission is created in a managed cluster's namespace on the hub and contains the RoleBindings and ClusterRoleBindings that should be applied to that cluster.

## Design: One ClusterPermission per MRA per Managed Cluster

Each `MulticlusterRoleAssignment` creates a **dedicated** `ClusterPermission` for each of its target managed clusters. This design ensures:

- **No shared resource contention**: Each MRA owns and controls its own ClusterPermission
- **Isolation**: Changes to one MRA never affect another MRA's ClusterPermission
- **Scalability**: Avoids the ManifestWork 512KB size limit that can occur with shared ClusterPermissions
- **Simplified ownership**: No per-binding owner tracking needed

### Resource Naming

ClusterPermission names follow the pattern:
```
mra-<sanitized-mra-name>-<8-char-hash>
```

- The hash is derived from the MRA's `namespace/name` for uniqueness
- The name is DNS-valid and ≤63 characters
- The same MRA uses the same ClusterPermission name on every target cluster

### Example

Given an MRA:
```yaml
apiVersion: rbac.open-cluster-management.io/v1beta1
kind: MulticlusterRoleAssignment
metadata:
  name: ldap-team-a
  namespace: open-cluster-management-global-set
spec:
  subject:
    kind: Group
    name: ldap-team-a
  roleAssignments:
  - name: view-access
    clusterRole: view
    clusterSelection:
      type: placements
      placements:
      - name: prod-clusters  # selects: cluster-a, cluster-b
  - name: edit-access
    clusterRole: edit
    clusterSelection:
      type: placements
      placements:
      - name: prod-clusters
  - name: admin-access
    clusterRole: admin
    clusterSelection:
      type: placements
      placements:
      - name: prod-clusters
```

This creates:
```
cluster-a/mra-ldap-team-a-a1b2c3d4
  └── ClusterRoleBindings: view, edit, admin (3 bindings)

cluster-b/mra-ldap-team-a-a1b2c3d4
  └── ClusterRoleBindings: view, edit, admin (3 bindings)
```

**Important**: All bindings from one MRA for one target cluster are grouped into a single ClusterPermission. We do **not** create one ClusterPermission per binding.

### Resource Count Formula

```
Number of ClusterPermissions = Number of MRAs × Number of selected managed clusters
```

**Example**: 100 MRAs, each with view/edit/admin roles, targeting 12 clusters:
- ClusterPermissions: 100 × 12 = **1,200**
- Total bindings: 100 × 3 × 12 = **3,600** (distributed across those 1,200 ClusterPermissions)

## Labels and Annotations

Each dedicated ClusterPermission has:

| Metadata | Key | Value |
|----------|-----|-------|
| Label | `rbac.open-cluster-management.io/managed-by` | `multiclusterroleassignment-controller` |
| Annotation | `rbac.open-cluster-management.io/mra-owner` | `<mra-namespace>/<mra-name>` |

### Why Not ownerReferences?

Kubernetes `ownerReferences` require the owner and owned resource to be in the same namespace. Since an MRA (in namespace `open-cluster-management-global-set`) creates ClusterPermissions in different managed cluster namespaces (e.g., `cluster-a`, `cluster-b`), cross-namespace owner references are invalid.

Instead, the `rbac.open-cluster-management.io/mra-owner` annotation identifies the owning MRA. The controller watches ClusterPermission changes and uses this annotation to enqueue the correct MRA for reconciliation.

## Lifecycle Behavior

### Create/Update

When an MRA is created or updated:
1. Calculate the dedicated ClusterPermission name: `mra-<sanitized-name>-<hash>`
2. For each target cluster:
   - Create or update the dedicated ClusterPermission with all bindings
   - Clean up any bindings from the legacy shared ClusterPermission (migration)

### Placement Change

When a cluster is removed from a Placement:
1. The dedicated ClusterPermission for that MRA in that cluster namespace is deleted
2. Other MRAs' ClusterPermissions in that namespace are unaffected

### Deletion

When an MRA is deleted:
1. The finalizer prevents immediate deletion
2. All dedicated ClusterPermissions for this MRA are deleted
3. Any remaining bindings in legacy shared ClusterPermissions are cleaned up
4. The finalizer is removed

## Migration from Legacy Shared Model

### Legacy Design (Pre-migration)

Previously, all MRAs targeting the same cluster shared a single ClusterPermission named `mra-managed-permissions`:
```
cluster-a/mra-managed-permissions
  └── All bindings from all MRAs targeting cluster-a
```

This design hit the ManifestWork 512KB size limit when many MRAs targeted the same cluster. See [ACM Troubleshooting Documentation](https://docs.redhat.com/en/documentation/red_hat_advanced_cluster_management_for_kubernetes/2.17/html/troubleshooting/troubleshooting#troubleshooting-multicluster-roleassign).

### Migration Process

Migration is automatic and gradual:

1. **On MRA reconciliation**: The dedicated ClusterPermission is created/updated first
2. **After success**: The MRA's bindings are removed from the legacy `mra-managed-permissions`
3. **Preserve others**: Bindings owned by other MRAs remain in the legacy ClusterPermission
4. **Final cleanup**: The legacy ClusterPermission is deleted only when empty (no MRA-owned bindings remain)

**Temporary duplicate bindings** during migration are acceptable and harmless (RBAC is idempotent). **Losing bindings is not acceptable**.

### Legacy Owner Annotations

The legacy shared ClusterPermission used per-binding owner annotations:
```yaml
annotations:
  owner/<binding-name>: <mra-namespace>/<mra-name>
```

During migration, these annotations are used to identify which bindings belong to which MRA and should be removed from the legacy ClusterPermission after migration to the dedicated model.

## Remaining Limits

While this design solves the problem of multiple MRAs hitting the ManifestWork size limit, a **single very large MRA** can still exceed the limit if it contains too many bindings.

**Mitigation**: Split very large MRAs into multiple smaller MRAs. For example, if one MRA has 100 roleAssignments each targeting 50 namespaces, consider splitting it into 10 MRAs with 10 roleAssignments each.

## Event Handling

The controller watches ClusterPermission changes and uses the `rbac.open-cluster-management.io/mra-owner` annotation to efficiently enqueue only the owning MRA for reconciliation.

For legacy ClusterPermissions (during migration), the handler falls back to the per-binding `owner/*` annotations to enqueue all affected MRAs.
