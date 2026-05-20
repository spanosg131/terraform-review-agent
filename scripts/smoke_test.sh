#!/usr/bin/env bash
# Verify every bundled scanner binary resolves on PATH and the agent imports.
# Run as a Docker build step (fails the build on a missing binary) and in CI
# against the built image.
set -euo pipefail

bins=(terraform tfsec tflint infracost checkov)

fail=0
for b in "${bins[@]}"; do
  if ! path="$(command -v "$b" 2>/dev/null)"; then
    printf 'MISS %-10s not found on PATH\n' "$b" >&2
    fail=1
    continue
  fi
  # Actually execute the binary: a wrong-arch or truncated binary is present
  # and executable-bit-set (so `command -v` succeeds) but fails to run.
  if out="$("$b" --version 2>&1)"; then
    printf 'ok   %-10s %s  (%s)\n' "$b" "$path" "$(printf '%s' "$out" | head -n1)"
  else
    printf 'FAIL %-10s %s  (--version exited non-zero — wrong arch or broken binary)\n' "$b" "$path" >&2
    fail=1
  fi
done

if python -c "import terraform_review_agent.entrypoint" 2>/dev/null; then
  printf 'ok   %-10s module imports\n' "agent"
else
  printf 'MISS %-10s terraform_review_agent.entrypoint failed to import\n' "agent" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "smoke test FAILED" >&2
  exit 1
fi
echo "smoke test passed"
