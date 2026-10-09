---
name: kubevirt-migration-rbac-sync
description: >-
  Compares acm-vm-extended:view and acm-vm-extended:admin migration rules in
  multicluster-role-assignment against kubevirt/kubevirt-migration-operator
  pkg/resources/cluster/rbac.go. Use when updating ACM-47215 virt RBAC,
  kubevirt migration ClusterRoles, or when CI reports migration RBAC drift.
---

# KubeVirt migration RBAC sync (ACM extended roles)

## Source of truth

| ACM role | Upstream equivalent |
|----------|---------------------|
| `acm-vm-extended:view` | `migrations.kubevirt.io:view` → `getViewPolicyRules()` |
| `acm-vm-extended:admin` | `migrations.kubevirt.io:storagemigrate` + `storagemigrate-multins` → `getStorageMigratePolicyRules()` + `getStorageMigrateMultinsPolicyRules()` |

Upstream file (track on `main` unless release pinning is agreed):

- [kubevirt/kubevirt-migration-operator `pkg/resources/cluster/rbac.go`](https://github.com/kubevirt/kubevirt-migration-operator/blob/main/pkg/resources/cluster/rbac.go)

ACM manifest to keep aligned:

- `charts/fine-grained-rbac/templates/acm-roles-addontemplate.yaml`

Standalone migration roles are **not** re-labeled in `policy-virt-clusterroles-policy.yaml`; permissions are folded into the extended roles only.

## Run the drift check locally

```bash
python3 hack/check-kubevirt-migration-rbac-sync.py
```

Exit `0` = match; `1` = drift; `2` = could not reach upstream.

## When upstream rbac.go changes

1. Run the script above and read the printed expected vs actual rules.
2. Update the `migrations.kubevirt.io` rule blocks under `acm-vm-extended:view` and `:admin` in the add-on template.
3. Do **not** grant migration write verbs on `:view` (admin only).
4. Open PR with Jira link; mention upstream commit or release if pinning.

## CI alarm (no cross-repo webhook required)

GitHub Actions workflow `.github/workflows/kubevirt-migration-rbac-drift.yml`:

- Runs on PRs that touch virt RBAC manifests or the checker.
- Runs on a **weekly schedule** (Monday 09:00 UTC) so upstream changes surface even without an MRA PR.
- Fails the job when drift is detected (treat as an alarm in GitHub notifications / required check).
- On exit code **1** (drift) or **2** (upstream fetch failure), posts to Slack channel [C0BKJ8P30J1](https://redhat.enterprise.slack.com/archives/C0BKJ8P30J1) via `chat.postMessage` when the repo secret **`SLACK_BOT_TOKEN`** is set (bot must be invited to that channel).

### Slack setup (one-time, repo admins)

1. Create or reuse a Slack app/bot with `chat:write` (and `chat:write.public` if the bot is not yet in the channel).
2. Add repository secret `SLACK_BOT_TOKEN` on `stolostron/multicluster-role-assignment` (and fork if testing Actions there).
3. `/invite @<bot>` in the target channel.

If the secret is missing, the workflow still fails on drift but logs a warning instead of posting to Slack.

### Optional: instant notification on upstream changes

GitHub cannot receive webhooks from `kubevirt/kubevirt-migration-operator` into this repo without org-level setup. Practical options:

1. **Weekly schedule + PR check** (already in repo) — default.
2. **Fork workflow**: In a fork of kubevirt-migration-operator, add a workflow that `repository_dispatch`es to `stolostron/multicluster-role-assignment` when `rbac.go` changes (needs a PAT and maintainer approval).
3. **Renovate / dependency bot**: Not applicable to copied rules; use the drift job instead.

## Agent checklist

- [ ] Fetched or read current `rbac.go` from kubevirt-migration-operator
- [ ] View role includes only `get` / `list` / `watch` on all four migration resources
- [ ] Admin role includes union of storagemigrate + multins verbs on the correct resource sets
- [ ] `python3 hack/check-kubevirt-migration-rbac-sync.py` passes
- [ ] Policy template does not re-add discoverable labels for the three standalone migration ClusterRoles unless product asks
