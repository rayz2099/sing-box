#!/usr/bin/env bash
set -euo pipefail

# Sync an upstream tag into a local build branch, bring in local workflow from main,
# then push branch to origin.
#
# Usage:
#   ./scripts/sync-upstream-tag.sh v1.13.0
#
# Optional env overrides:
#   UPSTREAM_REMOTE=upstream
#   ORIGIN_REMOTE=origin
#   MAIN_BRANCH=main
#   WORKFLOW_FILE=.github/workflows/docker-build-push.yml

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "Usage: $0 <tag>  (e.g. v1.13.0)"
  exit 1
fi

UPSTREAM_REMOTE="${UPSTREAM_REMOTE:-upstream}"
ORIGIN_REMOTE="${ORIGIN_REMOTE:-origin}"
MAIN_BRANCH="${MAIN_BRANCH:-main}"
WORKFLOW_FILE="${WORKFLOW_FILE:-.github/workflows/docker-build-push.yml}"
BUILD_BRANCH="build/${TAG}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: current directory is not a git repository."
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is not clean. Please commit or stash changes first."
  exit 1
fi

if ! git remote get-url "$UPSTREAM_REMOTE" >/dev/null 2>&1; then
  echo "Error: remote '$UPSTREAM_REMOTE' not found."
  exit 1
fi

if ! git remote get-url "$ORIGIN_REMOTE" >/dev/null 2>&1; then
  echo "Error: remote '$ORIGIN_REMOTE' not found."
  exit 1
fi

echo "==> Fetching tags from $UPSTREAM_REMOTE"
git fetch "$UPSTREAM_REMOTE" --tags

if ! git ls-remote --tags "$UPSTREAM_REMOTE" "refs/tags/$TAG" | grep -q .; then
  echo "Error: tag '$TAG' not found on remote '$UPSTREAM_REMOTE'."
  exit 1
fi

if ! git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "Error: local tag '$TAG' not found after fetch."
  exit 1
fi

echo "==> Creating/resetting branch $BUILD_BRANCH from tag $TAG"
git checkout -B "$BUILD_BRANCH" "refs/tags/$TAG"

if ! git show "$MAIN_BRANCH:$WORKFLOW_FILE" >/dev/null 2>&1; then
  echo "Error: '$WORKFLOW_FILE' not found on branch '$MAIN_BRANCH'."
  exit 1
fi

echo "==> Bringing workflow from $MAIN_BRANCH"
git checkout "$MAIN_BRANCH" -- "$WORKFLOW_FILE"

if [[ -n "$(git status --porcelain -- "$WORKFLOW_FILE")" ]]; then
  echo "==> Committing workflow update"
  git add "$WORKFLOW_FILE"
  git commit -m "ci: sync docker workflow for $TAG build"
else
  echo "==> Workflow unchanged, no commit needed"
fi

echo "==> Pushing branch to $ORIGIN_REMOTE"
git push -u "$ORIGIN_REMOTE" "$BUILD_BRANCH"

echo
echo "Done: $BUILD_BRANCH"
echo "Next: run workflow docker-build-push.yml with:"
echo "  ref = $BUILD_BRANCH"
echo "  tag = $TAG"
