# vault-ssh-cert-action

A GitHub Action that has the
[SSH secrets engine](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
of HashiCorp Vault sign a short-lived SSH certificate, and loads it into a
private `ssh-agent` for the rest of the job. It works the same with
[OpenBao](https://openbao.org).

- **The private key never touches the disk.** It is generated in memory, sent
  straight to the agent, and the agent drops it when the certificate expires.
- **It cleans up after itself.** At the end of the job, even after a failure,
  it removes the key from the agent, stops the agent and revokes the Vault
  token.
- **It does not log in.** Run
  [`hashicorp/vault-action`](https://github.com/hashicorp/vault-action) first
  with `exportToken: true`; this action uses its `VAULT_TOKEN`. Like the Vault
  CLI it reads the address from `VAULT_ADDR`, which vault-action does not
  export, so set it on the job and pass it to vault-action too.

## Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    env:
      VAULT_ADDR: https://vault.example.com
    steps:
      - uses: hashicorp/vault-action@<sha> # v4.0.0
        with:
          url: ${{ env.VAULT_ADDR }}
          method: jwt
          path: github-actions
          role: deploy-my-repo
          exportToken: true
      - uses: vexxhost/vault-ssh-cert-action@<sha> # v2.1.0
        with:
          ssh-role: deploy
          principals: deploy:my-repo
      - run: ansible-playbook -i inventory site.yml
```

The action exports `SSH_AUTH_SOCK` (and `SSH_AGENT_PID`), so `ssh`, `scp`,
`rsync`, `git` and Ansible in later steps use the certificate with no further
configuration.

The token is revoked at the end of the job, not right after signing, so later
steps can keep using it (for instance to sign host keys). Set
`revoke-token: false` to leave it alone.

### Binding the certificate to the runner

With `add-public-ip: true`, the certificate only works from the SSH role's
default `source-address` plus the runner's own public IPv4 address, so a stolen
certificate is useless elsewhere. Requested critical options replace the role's
defaults, so the action reads the role first and adds a `/32` for the runner:

- On GitHub-hosted runners the address comes from Azure's instance metadata
  service (the outbound address of the load balancer the runner goes out
  through), without leaving Azure. Note that GitHub runners share these
  outbound addresses.
- Elsewhere it asks `https://ipv4.icanhazip.com`.
- If neither answers, or the role has no default `source-address`, the step
  fails rather than signing an unrestricted certificate.

The token needs `read` on `<ssh-path>/roles/<ssh-role>`, the role needs
`allowed_critical_options` to include `source-address`, and the policy must not
deny `critical_options`. Vault cannot restrict the requested value, so this
protects against a stolen certificate, not a stolen token: keep tokens
short-lived and revoked (this action revokes them at the end of the job).

If something else in the job also sets `VAULT_TOKEN` (another vault-action
login, say), log in with `outputToken: true` instead and pass
`token: ${{ steps.<login>.outputs.vault_token }}`.

### Inputs

| Input | Default | |
|---|---|---|
| `ssh-role` | | SSH role to sign with. Required. |
| `principals` | role's `default_user` | Comma-separated `valid_principals`. |
| `ttl` | role's | Certificate TTL. |
| `ssh-path` | `ssh-client-signer` | Mount path of the SSH secrets engine. |
| `url` | `$VAULT_ADDR` | Vault address. |
| `token` | `$VAULT_TOKEN` | Vault token. |
| `add-public-ip` | `false` | Restrict the certificate to the role's `source-address` plus the runner's public IP. |
| `revoke-token` | `true` | Revoke the token at the end of the job. |

### Outputs

| Output | |
|---|---|
| `ssh-auth-sock` | The agent's socket (also exported as `SSH_AUTH_SOCK`). |
| `certificate` | The signed certificate. |
| `public-key` | The certified public key. |

The step fails with Vault's error message if signing is refused.

## Vault side

All restrictions belong in Vault:

- The **SSH role**'s `allowed_users` limits the principals a workflow may
  request. With `allow_empty_principals: false` and an empty `default_user`,
  the workflow must name its principal. Keys are ed25519, so
  `allowed_user_key_lengths` must allow it.
- The token's policy needs `update` on `<ssh-path>/sign/<ssh-role>`. A policy's
  `required_parameters` / `allowed_parameters` on `valid_principals` can narrow
  a shared role per login.
- The **JWT role** vault-action logs in with decides which repositories and
  workflows get that policy (`bound_claims`, `bound_subject`,
  `bound_audiences`).

## Development

```console
$ npm ci
$ npm test          # needs ssh-agent, ssh-add and ssh-keygen
$ npm run build     # commit dist/ with your change
```

CI also runs the action against a throwaway OpenBao that trusts the job's
GitHub OIDC token, and logs in to an `sshd` that trusts its CA.

## License

Apache 2.0.
