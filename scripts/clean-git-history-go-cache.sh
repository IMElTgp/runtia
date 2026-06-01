#!/usr/bin/env bash

set -euo pipefail

if ! git rev-parse --show-toplevel >/dev/null 2>&1; then
  echo "error: not inside a git repository" >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

echo "Repo: $repo_root"
echo "Rewriting history to remove go/ and .cache/ ..."

FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --force \
  --index-filter 'git rm -r --cached --ignore-unmatch go .cache' \
  --prune-empty \
  --tag-name-filter cat \
  -- --all

echo "Dropping filter-branch backups and unreachable objects ..."

rm -rf .git/refs/original/
git reflog expire --expire=now --all
git gc --prune=now --aggressive

echo
echo "Current .git size:"
du -sh .git

echo
echo "Current object stats:"
git count-objects -vH

echo
echo "Residual history entries for go/ or .cache/:"
matches="$(git rev-list --objects --all | grep -E ' (go/|\\.cache/)' || true)"
if [[ -n "$matches" ]]; then
  echo "$matches"
  echo
  echo "warning: matching paths are still present in history" >&2
  exit 2
fi

echo "none"
echo
echo "Done. If you need to update the remote, run:"
echo "  git push --force-with-lease origin main"
