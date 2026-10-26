# vault-ssh-cert-action

A composite GitHub Action that generates an SSH key and has the
[SSH secrets engine](https://developer.hashicorp.com/vault/docs/secrets/ssh/signed-ssh-certificates)
of HashiCorp Vault sign it for the principals you ask for. It works the same
with [OpenBao](https://openbao.org).

It does not log in: run [`hashicorp/vault-action`](https://github.com/hashicorp/vault-action)
first with `exportToken: true`, and this action uses its `VAULT_TOKEN`. Like
the Vault CLI, it reads the address from `VAULT_ADDR`, which vault-action does
not export, so set it on the job and pass it to vault-action too.

It needs only `curl`, `jq` and `ssh-keygen`, all present on GitHub's runners.

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
      - id: ssh
        uses: vexxhost/vault-ssh-cert-action@<sha> # v1.0.0
        with:
          ssh-role: deploy
          principals: deploy:my-repo
      - run: ansible-playbook -i inventory --private-key "$SSH_KEY" site.yml
        env:
          SSH_KEY: ${{ steps.ssh.outputs.key-path }}
```

The certificate is written next to the key as `<key>-cert.pub`, so `ssh -i
<key>` (and Ansible's `--private-key`) picks it up without further
configuration. Both live in `$RUNNER_TEMP`, which is emptied at the end of the
job.

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
| `key-type` | `ed25519` | `ssh-keygen -t`. |
| `url` | `$VAULT_ADDR` | Vault address. |
| `token` | `$VAULT_TOKEN` | Vault token. |

### Outputs

| Output | |
|---|---|
| `key-path` | Private key. |
| `cert-path` | Signed certificate (`<key-path>-cert.pub`). |

The step fails with Vault's error message if signing is refused; use
`continue-on-error` to treat the certificate as optional.

## Vault side

All restrictions belong in Vault:

- The **SSH role**'s `allowed_users` limits the principals a workflow may
  request. With `allow_empty_principals: false` and an empty `default_user`,
  the workflow must name its principal.
- The token's policy needs `update` on `<ssh-path>/sign/<ssh-role>`. A policy's
  `required_parameters` / `allowed_parameters` on `valid_principals` can narrow
  a shared role per login.
- The **JWT role** vault-action logs in with decides which repositories and
  workflows get that policy (`bound_claims`, `bound_subject`,
  `bound_audiences`).

## License

Apache 2.0.
