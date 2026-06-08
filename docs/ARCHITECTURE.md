# Architecture

## System overview

The MulticlusterRoleAssignment (MRA) operator runs on an ACM hub cluster and manages fine-grained RBAC across managed clusters. It translates high-level role assignment intent into per-cluster `ClusterPermission` resources, which the OCM framework propagates to managed clusters to create the actual `RoleBinding` / `ClusterRoleBinding` resources.

```
User creates MRA ─→ Controller reconciles ─→ ClusterPermission per cluster ─→ RoleBindings on managed clusters
```

## Component layers

### API layer (`api/`)

- **v1beta1** (served version): `MulticlusterRoleAssignment` spec with `Subject`, `RoleAssignment[]`, and `ClusterSelection`. CEL validation rules enforce constraints (e.g., ServiceAccount requires namespace, User/Group must not have namespace).
- **v1alpha1** (stored version): Legacy types kept for conversion webhook compatibility. No CEL validation rules.

### Controller layer (`internal/controller/`)

**`MulticlusterRoleAssignmentReconciler`** — the single reconciler handles the full lifecycle:

1. **Cluster resolution:** Reads `PlacementDecision` resources referenced by the MRA's `clusterSelection` to determine target clusters.
2. **ClusterPermission management:** Creates/updates/deletes `ClusterPermission` resources in each target cluster's namespace on the hub. Each ClusterPermission is named deterministically using a SHA-256 hash of the MRA identity.
3. **Status aggregation:** Reads back `ClusterPermission` status from each cluster to compute the MRA's aggregate status (Applied, Pending, Error conditions with per-cluster detail).
4. **Cleanup:** Uses finalizers to delete orphaned `ClusterPermission` resources when an MRA is deleted or clusters are removed from a placement.

**`ClusterPermissionEventHandler`** — watches `ClusterPermission` changes and enqueues the owning MRA for re-reconciliation, enabling status updates when downstream resources change.

**Field indexes** — `SetupIndexes()` creates indexes on MRA resources by Placement reference for efficient lookup when a Placement changes.

### Utilities (`internal/utils/`)

Shared helpers for label construction, deterministic naming, and common string operations used by both the controller and event handler.

## Data flow

```
┌─────────────────────────────────────────────────────────────┐
│                        Hub Cluster                          │
│                                                             │
│  MRA CR ──→ Reconciler ──→ ClusterPermission (per cluster)  │
│                ↑                     │                       │
│                │                     ↓                       │
│  PlacementDecision ──────── Managed Cluster Namespace       │
│  (cluster list)              (on hub, e.g. "cluster-a")     │
│                                                             │
│  ClusterPermission Status ──→ Reconciler ──→ MRA Status     │
│  (from managed clusters)       (aggregated conditions)      │
└─────────────────────────────────────────────────────────────┘
                                   │
                                   ↓ (OCM framework)
┌─────────────────────────────────────────────────────────────┐
│              Managed Clusters (cluster-a, cluster-b, ...)   │
│                                                             │
│  ClusterPermission agent creates:                           │
│    - ClusterRoleBindings (cluster-scoped roles)             │
│    - RoleBindings (namespaced roles in targetNamespaces)    │
└─────────────────────────────────────────────────────────────┘
```

## Deployment model

- **Production (ACM):** Deployed via Helm chart (`charts/fine-grained-rbac/`) as part of ACM. The chart includes the operator Deployment, RBAC, an OCM `AddonTemplate` for the cluster-permission agent, and governance policies for virtualization RBAC.
- **Development:** `make run` runs the controller locally against the current kubeconfig. `make deploy` deploys to a cluster via Kustomize.
- **Testing:** Unit tests use envtest (in-memory API server). E2E tests use Kind with the CRD installed and a locally-running controller.

## Key design decisions

- **Deterministic naming:** ClusterPermission names are SHA-256 hashes of `{MRA namespace}/{MRA name}/{role assignment name}`, avoiding conflicts and enabling garbage collection.
- **Placement-based cluster selection:** Rather than listing clusters directly, MRAs reference `Placement` resources, integrating with OCM's cluster scheduling.
- **CEL validation over webhooks:** Validation is done via CEL rules in the CRD schema rather than admission webhooks, reducing operational complexity. Uses `__namespace__` syntax for OLMv1 compatibility.
- **Finalizer-based cleanup:** The controller adds a finalizer to ensure ClusterPermission resources are cleaned up when an MRA is deleted.
- **Status aggregation with cluster-level detail:** MRA status combines individual ClusterPermission statuses into aggregate conditions with per-cluster breakdown in the message.

## High-level architecture diagram

See `docs/highlevel-virt-features-architecture.mmd` for a Mermaid diagram showing how MRA fits into the broader ACM virtualization feature set, including the relationship to CNV Console, Search, Cluster Proxy, and cross-cluster live migration.
