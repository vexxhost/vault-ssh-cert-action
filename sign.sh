#!/usr/bin/env bash
# Generate an SSH key and have Vault's SSH secrets engine sign it, with the
# token a previous hashicorp/vault-action step logged in for.
set -euo pipefail

fail() {
  echo "::error title=Vault SSH certificate::$*"
  exit 1
}

url=${INPUT_URL:-${VAULT_ADDR:-}}
token=${INPUT_TOKEN:-${VAULT_TOKEN:-}}
[[ -n $url ]] || fail "no Vault address: set VAULT_ADDR (or the url input)"
[[ -n $token ]] || fail "no Vault token: log in first with hashicorp/vault-action and exportToken: true (or set the token input)"
[[ -n ${INPUT_SSH_ROLE:-} ]] || fail "input ssh-role is required"
ssh_path=${INPUT_SSH_PATH#/}
ssh_path=${ssh_path%/}
endpoint="${url%/}/v1/$ssh_path/sign/$INPUT_SSH_ROLE"

# RUNNER_TEMP is emptied at the end of every job, even on self-hosted runners.
dir=$(mktemp -d "$RUNNER_TEMP/vault-ssh-cert.XXXXXX")
key="$dir/id_$INPUT_KEY_TYPE"
ssh-keygen -q -t "$INPUT_KEY_TYPE" -N '' -C "$GITHUB_REPOSITORY@$GITHUB_RUN_ID" -f "$key"

request=$(jq -n --rawfile key "$key.pub" --arg principals "$INPUT_PRINCIPALS" --arg ttl "$INPUT_TTL" \
  '{public_key: $key} + if $principals != "" then {valid_principals: $principals} else {} end
    + if $ttl != "" then {ttl: $ttl} else {} end')
if ! response=$(curl -sS --fail-with-body -H "X-Vault-Token: $token" --data "$request" "$endpoint"); then
  fail "POST $endpoint: $(jq -r '(.errors // []) | join("; ")' <<<"$response" 2>/dev/null || printf '%s' "$response")"
fi
jq -er '.data.signed_key | rtrimstr("\n")' <<<"$response" >"$key-cert.pub" || fail "POST $endpoint returned no certificate"

ssh-keygen -L -f "$key-cert.pub"
{
  echo "key-path=$key"
  echo "cert-path=$key-cert.pub"
} >>"$GITHUB_OUTPUT"
