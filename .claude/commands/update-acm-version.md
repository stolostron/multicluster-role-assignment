# Update ACM Version Tekton Files

This command updates the Konflux pipeline files for a new ACM release version. It follows the pattern established in previous version updates where files are renamed (not created new) and version numbers are updated throughout.

## Background

Every ACM release, an automated PR adds new tekton pipeline files with the next version number. However, to maintain git history, we need to rename the previous version files instead of creating new ones.

## Pattern Analysis

Version updates follow this pattern:
- Rename existing `multicluster-role-assignment-acm-XXX-*.yaml` files to the new version
- Update all internal references to the new version number
- Update release branch references (e.g., `release-2.XX` to `release-2.YY`)
- Update labels, names, and image paths with new version

## Automatic Version Detection

The script will:
1. Detect OLD_VERSION: Find existing tekton files (e.g., `*-acm-216-*.yaml`)
2. Detect NEW_VERSION: Find newly added tekton files (e.g., `*-acm-217-*.yaml`)
3. Derive release versions: Extract minor version from ACM version (216→2.16, 217→2.17)

## Execution Steps

### Step 1: Detect Versions

```bash
# Find the old version (existing files, not newly added)
OLD_VERSION=$(ls .tekton/multicluster-role-assignment-acm-*-pull-request.yaml 2>/dev/null | grep -oP 'acm-\K\d+' | sort -n | head -1)

# Find the new version (from git diff - newly added files)
NEW_VERSION=$(git diff --name-only main .tekton/ | grep -oP 'acm-\K\d+' | sort -nu | tail -1)

# Derive release versions (e.g., 216 -> 2.16)
OLD_RELEASE="${OLD_VERSION:0:1}.${OLD_VERSION:1}"
NEW_RELEASE="${NEW_VERSION:0:1}.${NEW_VERSION:1}"

echo "Detected version change: ACM $OLD_VERSION -> $NEW_VERSION (release-$OLD_RELEASE -> release-$NEW_RELEASE)"
```

### Step 2: Delete the New Files (we'll recreate them via rename)

```bash
git rm .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
git rm .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml
```

### Step 3: Rename Old Files to New Version

```bash
# Using git mv to preserve history
git mv .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-pull-request.yaml \
       .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml

git mv .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-push.yaml \
       .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml
```

### Step 4: Update Content in Pull Request File

For `multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml`:

Replace all occurrences:
- `acm-${OLD_VERSION}` → `acm-${NEW_VERSION}` (everywhere)
- `release-acm-${OLD_VERSION}` → `release-acm-${NEW_VERSION}` (everywhere)
- `release-${OLD_RELEASE}` → `release-${NEW_RELEASE}` (in CEL expressions)

Key areas to update:
1. CEL expression: `pipelinesascode.tekton.dev/on-cel-expression: event == "pull_request" && (target_branch == "main" || target_branch == "release-X.XX")`
2. Labels: `appstudio.openshift.io/application: release-acm-XXX`
3. Labels: `appstudio.openshift.io/component: multicluster-role-assignment-acm-XXX`
4. Metadata name: `multicluster-role-assignment-acm-XXX-on-pull-request`
5. Output image: `quay.io/redhat-user-workloads/crt-redhat-acm-tenant/multicluster-role-assignment-acm-XXX:on-pr-{{revision}}`
6. Service account: `build-pipeline-multicluster-role-assignment-acm-XXX`
7. Konflux application name param: `release-acm-XXX` (if present)

Use global search and replace:

```bash
sed -i "s/acm-${OLD_VERSION}/acm-${NEW_VERSION}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml

sed -i "s/release-${OLD_RELEASE}/release-${NEW_RELEASE}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
```

### Step 5: Update Content in Push File

For `multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml`:

Same replacements as pull-request file:
- `acm-${OLD_VERSION}` → `acm-${NEW_VERSION}` (everywhere)
- `release-acm-${OLD_VERSION}` → `release-acm-${NEW_VERSION}` (everywhere)
- `release-${OLD_RELEASE}` → `release-${NEW_RELEASE}` (in CEL expressions)

Additional areas specific to push file:
1. CEL expression: `pipelinesascode.tekton.dev/on-cel-expression: event == "push" && target_branch == "release-X.XX"`

Use global search and replace:

```bash
sed -i "s/acm-${OLD_VERSION}/acm-${NEW_VERSION}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml

sed -i "s/release-${OLD_RELEASE}/release-${NEW_RELEASE}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml
```

## Verification

After making changes:

```bash
# Should show renamed files, not new files
git status

# Should show only version number changes in the diff
git diff --cached

# Verify the pattern matches previous version updates
git log --all --oneline --grep="Konflux pipeline" | head -5

# Compare with previous version update commit
git show b58c96e --stat
```

Expected `git status` output:
```
renamed:    .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-pull-request.yaml -> .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
renamed:    .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-push.yaml -> .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml
```

## Automated Script

For convenience, here's a complete automated script:

```bash
#!/bin/bash
set -e

# Detect versions
OLD_VERSION=$(ls .tekton/multicluster-role-assignment-acm-*-pull-request.yaml 2>/dev/null | grep -oP 'acm-\K\d+' | sort -n | head -1)
NEW_VERSION=$(git diff --name-only main .tekton/ | grep -oP 'acm-\K\d+' | sort -nu | tail -1)

if [ -z "$OLD_VERSION" ] || [ -z "$NEW_VERSION" ]; then
  echo "Error: Could not detect versions"
  exit 1
fi

OLD_RELEASE="${OLD_VERSION:0:1}.${OLD_VERSION:1}"
NEW_RELEASE="${NEW_VERSION:0:1}.${NEW_VERSION:1}"

echo "Updating ACM $OLD_VERSION -> $NEW_VERSION (release-$OLD_RELEASE -> release-$NEW_RELEASE)"

# Delete new files
git rm .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
git rm .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml

# Rename old files
git mv .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-pull-request.yaml \
       .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
git mv .tekton/multicluster-role-assignment-acm-${OLD_VERSION}-push.yaml \
       .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml

# Update content
sed -i "s/acm-${OLD_VERSION}/acm-${NEW_VERSION}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml
sed -i "s/release-${OLD_RELEASE}/release-${NEW_RELEASE}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-pull-request.yaml

sed -i "s/acm-${OLD_VERSION}/acm-${NEW_VERSION}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml
sed -i "s/release-${OLD_RELEASE}/release-${NEW_RELEASE}/g" \
  .tekton/multicluster-role-assignment-acm-${NEW_VERSION}-push.yaml

echo "Done! Review changes with: git status && git diff --cached"
```

## Notes

- This process only handles the `.tekton/` directory files
- Other files in the diff (go.mod, cmd/main.go, controller files) are separate changes and should not be modified as part of the version bump
- The version numbering follows the pattern: 3-digit ACM version (e.g., 217) maps to release version (e.g., 2.17)
