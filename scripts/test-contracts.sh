#!/usr/bin/env bash
set -euo pipefail

for project in packages/contracts packages/contracts-experimental packages/pq/verifiers/c10 packages/pq/verifiers/mldsa; do
  echo "Testing $project"
  (cd "$project" && forge test)
done
