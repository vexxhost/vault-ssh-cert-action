#!/usr/bin/env bash
# Log in to OpenBao with the job's GitHub OIDC token and sign a fresh SSH key.
# Inputs come from action.yml as INPUT_* environment variables.
set -euo pipefail

fail() {
  echo "::error title=OpenBao SSH certificate::$*"
  exit 1
}

# Call OpenBao; print the response body, or fail with OpenBao's errors.
bao() {
  local method=$1 path=$2 body=${3:-} response status
  local args=(-sS -X "$method" -w '\n%{http_code}' -H "Content-Type: application/json")
  if [[ -n ${token:-} ]]; then
    args+=(-H "X-Vault-Token: $token")
  fi
  if [[ -n $body ]]; then
    args+=(--data @-)
  fi
  response=$(curl "${args[@]}" "$url/v1/$path" <<<"$body") || fail "$method $path: request failed"
  status=${response##*$'\n'}
  response=${response%$'\n'*}
  if [[ $status != 2* ]]; then
    fail "$method $path: HTTP $status: $(jq -r '(.errors // []) | join("; ")' <<<"$response" 2>/dev/null)"
  fi
  printf '%s' "$response"
}

for name in URL ROLE SSH_ROLE; do
  var=INPUT_$name
  [[ -n ${!var:-} ]] || fail "input ${name,,} is required"
done
if [[ -z ${ACTIONS_ID_TOKEN_REQUEST_URL:-} || -z ${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-} ]]; then
  fail "no GitHub OIDC token available: the job needs 'permissions: id-token: write'"
fi

url=${INPUT_URL%/}
auth_path=${INPUT_AUTH_PATH:-github-actions}
auth_path=${auth_path#/}
auth_path=${auth_path%/}
ssh_path=${INPUT_SSH_PATH:-ssh-client-signer}
ssh_path=${ssh_path#/}
ssh_path=${ssh_path%/}

# GitHub OIDC token. Without an audience parameter GitHub uses its default,
# https://github.com/<owner>.
oidc_url=$ACTIONS_ID_TOKEN_REQUEST_URL
if [[ -n ${INPUT_AUDIENCE:-} ]]; then
  oidc_url+="&audience=$(jq -rn --arg a "$INPUT_AUDIENCE" '$a | @uri')"
fi
jwt=$(curl -fsS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$oidc_url" | jq -er .value) ||
  fail "could not get a GitHub OIDC token"
echo "::add-mask::$jwt"

login=$(jq -n --arg role "$INPUT_ROLE" --arg jwt "$jwt" '{role: $role, jwt: $jwt}')
token=$(bao POST "auth/$auth_path/login" "$login" | jq -er .auth.client_token) ||
  fail "login to auth/$auth_path as role $INPUT_ROLE returned no token"
echo "::add-mask::$token"

revoke() {
  if [[ ${INPUT_REVOKE_TOKEN:-true} != false ]]; then
    bao POST auth/token/revoke-self >/dev/null || echo "::warning title=OpenBao SSH certificate::could not revoke the token"
  fi
}
trap revoke EXIT

# RUNNER_TEMP is emptied at the end of every job, even on self-hosted runners.
dir=$(mktemp -d "${RUNNER_TEMP:-/tmp}/openbao-ssh-cert.XXXXXX")
key="$dir/id_$INPUT_KEY_TYPE"
ssh-keygen -q -t "$INPUT_KEY_TYPE" -N '' -C "github-actions:$GITHUB_REPOSITORY:$GITHUB_RUN_ID" -f "$key"

request=$(jq -n --rawfile key "$key.pub" --arg principals "${INPUT_PRINCIPALS:-}" --arg ttl "${INPUT_TTL:-}" \
  '{public_key: $key} + (if $principals != "" then {valid_principals: $principals} else {} end)
    + (if $ttl != "" then {ttl: $ttl} else {} end)')
bao POST "$ssh_path/sign/$INPUT_SSH_ROLE" "$request" | jq -er '.data.signed_key | rtrimstr("\n")' >"$key-cert.pub" ||
  fail "$ssh_path/sign/$INPUT_SSH_ROLE returned no certificate"
chmod 600 "$key" "$key-cert.pub"

ssh-keygen -L -f "$key-cert.pub"

{
  echo "key-path=$key"
  echo "cert-path=$key-cert.pub"
  if [[ ${INPUT_REVOKE_TOKEN:-true} == false ]]; then
    echo "token=$token"
  fi
} >>"$GITHUB_OUTPUT"
