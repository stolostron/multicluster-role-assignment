# CLAUDE.md

## Project overview

Kubernetes operator for **MulticlusterRoleAssignment (MRA)** — manages cross-cluster RBAC by creating `ClusterPermission` resources on managed clusters via Open Cluster Management (OCM). Built with operator-sdk (Kubebuilder v4) in Go.

- **API group:** `rbac.open-cluster-management.io`
- **Active version:** `v1beta1` (legacy `v1alpha1` exists as stored version only)
- **Upstream:** Part of [stolostron](https://github.com/stolostron) / Red Hat Advanced Cluster Management (ACM)

## Build / test / lint commands

```bash
# Build
make build                  # Build manager binary to bin/manager

# Unit tests (requires envtest binaries — downloaded automatically)
make test                   # Runs go test on all packages except e2e, generates coverage.out

# E2E tests (requires Kind — must be pre-installed)
make test-e2e               # Creates Kind cluster, runs e2e tests via Ginkgo
make cleanup-test-e2e       # Tears down Kind cluster

# Lint
make lint                   # Runs golangci-lint (v2, config in .golangci.yml)
make lint-fix               # Lint with auto-fix

# Code generation (run after changing api/ types or RBAC markers)
make manifests              # Regenerate CRDs and RBAC from kubebuilder markers
make generate               # Regenerate deepcopy methods

# Formatting
make fmt                    # go fmt
make vet                    # go vet
```

### Running a single test

```bash
# Single package
go test ./internal/controller/ -run TestSpecificName -v

# E2E with Ginkgo focus
KUBECONFIG=$HOME/.kube/config go test ./test/e2e/ -v -ginkgo.v -ginkgo.focus="description pattern"
```

## Key directories

| Path | Purpose |
|------|---------|
| `cmd/main.go` | Operator entry point — registers schemes, creates manager |
| `api/v1beta1/` | CRD types, CEL validation markers, deepcopy |
| `api/v1alpha1/` | Legacy stored API version |
| `internal/controller/` | Reconciler, ClusterPermission event handler, field indexes |
| `internal/utils/` | Shared helpers (label building, naming) |
| `config/crd/bases/` | Generated CRD YAML |
| `config/rbac/` | Generated RBAC manifests |
| `charts/fine-grained-rbac/` | Helm chart for ACM deployment (includes addon templates, policies) |
| `test/e2e/` | Ginkgo e2e tests |
| `test/crd/` | Test-only CRD fixtures (ClusterPermission, Placement, PlacementDecision) |
| `hack/` | `sync-rbac-rules.sh` (syncs RBAC to Helm chart), `boilerplate.go.txt` |
| `.tekton/` | Konflux/Tekton pipeline definitions per ACM release |

For system architecture, data flows, and module layout, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## CRD and CEL validation

CEL validation rules use `self.__namespace__` (double-underscore syntax) for OLMv1 compatibility — `namespace` is a reserved keyword in newer CEL/OLMv1. String literals in CEL rules use double quotes (`"User"`, `"Group"`).

After modifying `XValidation` markers in `api/v1beta1/multiclusterroleassignment_types.go`, always run `make manifests` to regenerate the CRD YAML.

## CI systems

- **GitHub Actions:** lint, unit tests, e2e tests, RBAC validation (`.github/workflows/`)
- **Prow:** OpenShift CI for release branches (config lives in `openshift/release` repo)
- **Konflux/Tekton:** RHTAP pipelines per ACM version (`.tekton/`)
- **Dependabot + Renovate:** Automated dependency updates (`.github/dependabot.yml`, `.github/renovate.json`)

## Release branches

Release branches follow the pattern `release-X.YY` (e.g., `release-2.17`). Each release branch has corresponding Tekton pipeline files in `.tekton/`. Use the `/update-acm-version` Claude command when adding a new release version.

## RBAC sync

The operator's RBAC rules are defined via kubebuilder markers in the controller and synced to the Helm chart by `hack/sync-rbac-rules.sh`. The `validate-rbac` GitHub Action ensures they stay in sync. After changing RBAC markers, run `make manifests` — the sync script runs automatically as part of that target.

## Dockerfile variants

- `Dockerfile` — standard multi-stage build (`golang:1.25` → distroless runtime)
- `Dockerfile.rhtap` — Red Hat build with FIPS compliance (`GOEXPERIMENT=strictfipsruntime`), UBI-based runtime, CPE labels

## Personal configuration

Read `.claude/user.local.md` at the start of any task that needs an assignee, email, or project key.
If the file does not exist, fall back to Claude memory (`user-config`), then placeholders.
Run `make personalize` to generate it (if this repo uses Fleet Engineering tooling).

## Fleet Engineering Skills

Fetch and apply the relevant skill when the task matches its domain.

| Skill | When to use |
|---|---|
| [bug-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/bug-specialist/SKILL.md) | Bug triage, reproduction steps, fix planning |
| [epic-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/epic-specialist/SKILL.md) | Multi-sprint epics with outcomes |
| [feature-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/feature-specialist/SKILL.md) | Large customer-facing capabilities |
| [initiative-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/initiative-specialist/SKILL.md) | Multi-team strategic programs |
| [jira-create](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/jira-create/SKILL.md) | Interactive issue creation with specialist delegation |
| [jira-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/jira-specialist/SKILL.md) | General triage, search, linking, transitions |
| [outcome-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/outcome-specialist/SKILL.md) | Strategic outcomes tied to OKRs |
| [spike-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/spike-specialist/SKILL.md) | Time-boxed research and PoC |
| [story-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/story-specialist/SKILL.md) | User stories with acceptance criteria |
| [task-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/jira/task-specialist/SKILL.md) | Internal technical tasks |
| [agent-memory-setup](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/agent-memory-setup/SKILL.md) | Initialize or update CLAUDE.md / AGENTS.md for a repo |
| [finish-work](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/finish-work/SKILL.md) | Commit, push, open PR, update Jira |
| [pr-fix](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/pr-fix/SKILL.md) | Fix blocked PRs: merge conflicts, CI failures, review comments |
| [pr-review](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/pr-review/SKILL.md) | GitHub PR review with worktree isolation and inline comments |
| [repo-content-audit](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/repo-content-audit/SKILL.md) | Scan for unlinked or orphaned content — catalog gaps, dead links |
| [start-work](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/sdlc/start-work/SKILL.md) | Create a Jira sub-task |
| [f2f-daily-summary](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/meetings/f2f-daily-summary/SKILL.md) | Capture daily F2F meeting notes as Jira sub-tasks |
| [f2f-epic-specialist](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/meetings/f2f-epic-specialist/SKILL.md) | Create and manage F2F meeting Epics |
| [presentation-task](https://raw.githubusercontent.com/OpenShift-Fleet/agentic-sdlc/main/skills/meetings/presentation-task/SKILL.md) | Log a delivered presentation as a closed Jira sub-task |
