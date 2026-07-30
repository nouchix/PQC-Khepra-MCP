#!/usr/bin/env bash
# PreToolUse guard for Bash: blocks destructive rm -rf and direct pushes to
# main/master. Exit 2 blocks the call and feeds stderr back to Claude.
set -uo pipefail

input="$(cat)"
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
[[ -z "$cmd" ]] && exit 0

read -ra words <<< "$cmd"

prev=""
for w in "${words[@]}"; do
  if [[ "$prev" == "rm" ]] && [[ "$w" =~ ^-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*$ || "$w" =~ ^-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*$ ]]; then
    echo "Blocked: 'rm -rf' is destructive. Use 'trash', 'git clean' with -n first, or move the files instead." >&2
    exit 2
  fi
  prev="$w"
done

prev=""
found_push=0
for w in "${words[@]}"; do
  if [[ "$prev" == "git" && "$w" == "push" ]]; then
    found_push=1
  fi
  prev="$w"
done
if [[ "$found_push" -eq 1 ]]; then
  for w in "${words[@]}"; do
    if [[ "$w" == "main" || "$w" == "master" ]]; then
      echo "Blocked: direct push to '$w'. Push to a feature branch and open a PR instead." >&2
      exit 2
    fi
  done
fi

exit 0
