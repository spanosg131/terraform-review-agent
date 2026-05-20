#!/usr/bin/env sh
# Local end-to-end review that mirrors the CI workflow, all inside the container
# and using /tmp only (nothing is written to ./data):
#
#   1. clone the target repo with the GITHUB_TOKEN from .env
#   2. check out the PR's merge ref (falls back to the head ref)
#   3. build the infracost baseline from the merge commit's base parent (HEAD^1)
#   4. run the reviewer against the checked-out tree
#
# Invoked by `make review-local REPO=owner/repo PR=<number>`.
set -eu

: "${REPO:?set REPO=owner/repo}"
: "${PR:?set PR=<number>}"
: "${GITHUB_TOKEN:?GITHUB_TOKEN must be set (put it in .env)}"

work="$(mktemp -d)"
auth_url="https://x-access-token:${GITHUB_TOKEN}@github.com/${REPO}.git"

echo "cloning ${REPO} ..." >&2
git clone --quiet "$auth_url" "$work"
cd "$work"

# Prefer the merge ref (PR merged into base, like a pull_request checkout);
# fall back to the head ref for unmergeable PRs.
if git fetch --quiet origin "pull/${PR}/merge"; then
  git checkout --quiet FETCH_HEAD
else
  git fetch --quiet origin "pull/${PR}/head"
  git checkout --quiet FETCH_HEAD
fi

baseline=""
if [ -n "${INFRACOST_API_KEY:-}" ]; then
  base_sha="$(git rev-parse HEAD^1 2>/dev/null || true)"
  if [ -n "$base_sha" ]; then
    wt="/tmp/tfr-base-$$"
    git worktree add --quiet --detach "$wt" "$base_sha"
    if infracost breakdown --path "$wt" --format json --out-file /tmp/infracost-base.json 1>&2; then
      baseline="/tmp/infracost-base.json"
    else
      echo "infracost baseline failed; cost agent will be skipped" >&2
    fi
  fi
fi

echo "reviewing ${REPO}#${PR} (workspace=${work}, baseline=${baseline:-none}) ..." >&2
export WORKSPACE_DIR="$work"
export INFRACOST_BASELINE_PATH="$baseline"
exec python -m terraform_review_agent.entrypoint --repository "$REPO" --pr-number "$PR"
