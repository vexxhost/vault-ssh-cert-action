#!/usr/bin/env bash
# Start a dev OpenBao that trusts this job's GitHub OIDC tokens, and an sshd on
# port 2222 that trusts its SSH CA for the deploy:test and automation principals.
set -euo pipefail

docker run -d --name openbao -p 127.0.0.1:8200:8200 --cap-add IPC_LOCK "$OPENBAO_IMAGE" \
  server -dev -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200 >/dev/null
for _ in $(seq 30); do
  curl -fsS "$BAO_ADDR/v1/sys/health" >/dev/null 2>&1 && break
  sleep 1
done

bao() {
  curl -fsS -H "X-Vault-Token: root" -X POST --data "$2" "$BAO_ADDR/v1/$1"
}

issuer=https://token.actions.githubusercontent.com
bao sys/auth/github-actions '{"type": "jwt"}'
bao auth/github-actions/config "{\"oidc_discovery_url\": \"$issuer\", \"bound_issuer\": \"$issuer\"}"
bao sys/policies/acl/sign '{"policy": "path \"ssh-client-signer/sign/*\" { capabilities = [\"update\"] }"}'
jq -n --arg owner "$GITHUB_REPOSITORY_OWNER" --arg repo "$GITHUB_REPOSITORY" '{
  role_type: "jwt", user_claim: "sub", token_policies: ["sign"], token_ttl: "5m",
  bound_audiences: ["https://github.com/\($owner)", "openbao-ssh-cert-action-test"],
  bound_claims: {repository: $repo}
}' | bao auth/github-actions/role/ci "$(cat)"

bao sys/mounts/ssh-client-signer '{"type": "ssh"}'
bao ssh-client-signer/config/ca '{"generate_signing_key": true, "key_type": "ed25519"}' >/dev/null
role='{"key_type": "ca", "allow_user_certificates": true, "allow_empty_principals": false,
  "default_extensions": {"permit-pty": ""}, "allowed_extensions": "permit-pty", "ttl": "10m", "max_ttl": "10m"'
bao ssh-client-signer/roles/deploy "$role, \"allowed_users\": \"deploy:test\", \"default_user\": \"\"}"
bao ssh-client-signer/roles/automation "$role, \"allowed_users\": \"automation\", \"default_user\": \"automation\"}"

dir=$(mktemp -d)
curl -fsS "$BAO_ADDR/v1/ssh-client-signer/public_key" >"$dir/ca.pub"
printf 'deploy:test\nautomation\n' >"$dir/principals"
ssh-keygen -q -t ed25519 -N '' -f "$dir/host_key"
cat >"$dir/sshd_config" <<EOF
Port 2222
ListenAddress 127.0.0.1
HostKey $dir/host_key
PidFile $dir/sshd.pid
StrictModes no
UsePAM yes
PasswordAuthentication no
AuthorizedKeysFile none
TrustedUserCAKeys $dir/ca.pub
AuthorizedPrincipalsFile $dir/principals
EOF
sudo mkdir -p /run/sshd
sudo /usr/sbin/sshd -f "$dir/sshd_config"
