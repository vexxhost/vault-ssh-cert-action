# openbao-ssh-cert-action

A composite GitHub Action that logs in to [OpenBao](https://openbao.org) (or
HashiCorp Vault) with the job's GitHub OIDC token, generates a fresh SSH key
and has the SSH secrets engine sign it, for the principals you ask for.

It needs nothing but `bash`, `curl`, `jq` and `ssh-keygen`, all present on
GitHub's runners.

## Usage

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - id: ssh
        uses: vexxhost/openbao-ssh-cert-action@<sha> # v1
        with:
          url: https://openbao.example.com
          role: deploy-my-repo
          ssh-role: deploy
          principals: deploy:my-repo
      - run: ansible-playbook -i inventory site.yml
        env:
          ANSIBLE_PRIVATE_KEY_FILE: ${{ steps.ssh.outputs.key-path }}
```

The certificate is written next to the key as `<key>-cert.pub`, so
`ssh -i <key>` (and Ansible's `private_key_file`) picks it up without further
configuration. Both live in `$RUNNER_TEMP`, which is emptied at the end of the
job.

### Inputs

| Input | Default | |
|---|---|---|
| `url` | | OpenBao address. Required. |
| `role` | | JWT auth role to log in with. Required. |
| `auth-path` | `github-actions` | Mount path of the JWT auth method. |
| `audience` | GitHub's default | `aud` to request for the OIDC token. Empty leaves it to GitHub: `https://github.com/<owner>`. |
| `ssh-path` | `ssh-client-signer` | Mount path of the SSH secrets engine. |
| `ssh-role` | | SSH role to sign with. Required. |
| `principals` | role's `default_user` | Comma-separated `valid_principals`. |
| `ttl` | role's | Certificate TTL. |
| `key-type` | `ed25519` | `ssh-keygen -t`. |
| `revoke-token` | `true` | Revoke the OpenBao token after signing. Set to `false` to keep it for later steps (`token` output), e.g. when the same job also signs host keys. |

### Outputs

| Output | |
|---|---|
| `key-path` | Private key. |
| `cert-path` | Signed certificate (`<key-path>-cert.pub`). |
| `token` | OpenBao token, masked. Only set when `revoke-token` is `false`. |

The step fails, with OpenBao's error message, if the login or the signing is
refused; use `continue-on-error` to treat a certificate as optional.

## OpenBao side

All restrictions belong in OpenBao:

- **JWT auth** with `oidc_discovery_url` and `bound_issuer` set to
  `https://token.actions.githubusercontent.com`. Bind each role with
  `bound_claims` (`repository`, `job_workflow_ref`, ...) or `bound_subject`, and
  `bound_audiences` to the audience the workflow requests (by default
  `https://github.com/<owner>`).
- **SSH role** with `allowed_users` limited to the principals the workflow may
  request; with `allow_empty_principals: false` and an empty `default_user`,
  the workflow must name its principal. A policy's `required_parameters` /
  `allowed_parameters` on `valid_principals` can narrow a shared role per
  login.
- The login's policy needs `update` on `<ssh-path>/sign/<ssh-role>`.

## License

Apache 2.0.
