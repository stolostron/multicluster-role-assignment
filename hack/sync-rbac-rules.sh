#!/bin/bash
set -e

# Check if yq is available
if ! command -v yq &> /dev/null; then
    echo "ERROR: yq not found. Install with: go install github.com/mikefarah/yq/v4@latest" >&2
    exit 1
fi

SRC="config/rbac/role.yaml"
DST="charts/fine-grained-rbac/templates/multicluster-role-assignment-clusterrole.yaml"

echo "Syncing RBAC rules to installer chart..."

new_rules=$(yq eval '.rules' "$SRC" | sed 's/^/  /')
tmp_file="${DST}.tmp"

awk '/^rules:/ {exit} {print}' "$DST" > "$tmp_file"
echo "rules:" >> "$tmp_file"
echo "$new_rules" >> "$tmp_file"
mv "$tmp_file" "$DST"

echo "Installer chart RBAC updated"
