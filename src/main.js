import * as core from '@actions/core';
import { tmpdir } from 'node:os';

import { connection } from './inputs.js';
import {
  addCertificate,
  generateKey,
  parseCertificate,
  publicKeyLine,
  startAgent,
} from './ssh.js';
import { publicIp } from './publicip.js';
import { roleSourceAddress, signKey } from './vault.js';

async function run() {
  const { url, token } = connection();
  if (!url) {
    throw new Error('no Vault address: set VAULT_ADDR (or the url input)');
  }
  if (!token) {
    throw new Error(
      'no Vault token: log in first with hashicorp/vault-action and exportToken: true (or set the token input)',
    );
  }
  const role = core.getInput('ssh-role', { required: true });

  const comment = `${process.env.GITHUB_REPOSITORY ?? 'github-actions'}@${process.env.GITHUB_RUN_ID ?? 'local'}`;
  const { pub, seed } = generateKey();
  const publicKey = publicKeyLine(pub, comment);

  const sshPath = core.getInput('ssh-path') || 'ssh-client-signer';

  // Bind the certificate to the role's source addresses plus this runner's
  // public address. Requested critical options replace the role's defaults,
  // so start from those.
  let criticalOptions;
  if (core.getBooleanInput('add-public-ip')) {
    const base = await roleSourceAddress({ url, token, sshPath, role });
    if (!base) {
      throw new Error(`add-public-ip: SSH role ${role} has no default source-address to add to`);
    }
    const { address, source } = await publicIp();
    core.info(`Public IP ${address} (from ${source})`);
    criticalOptions = { 'source-address': `${base},${address}/32` };
  }

  const certificate = await signKey({
    url,
    token,
    sshPath,
    role,
    publicKey,
    principals: core.getInput('principals'),
    ttl: core.getInput('ttl'),
    criticalOptions,
  });
  const cert = parseCertificate(certificate);
  if (!cert.pub.equals(pub)) {
    throw new Error('the certificate is for a different key');
  }

  const now = BigInt(Math.floor(Date.now() / 1000));
  if (cert.validBefore <= now) {
    throw new Error('the certificate has already expired');
  }
  // The agent forgets the key when the certificate expires.
  const lifetime = Number(cert.validBefore - now < 0xffffffffn ? cert.validBefore - now : 0xffffffffn);

  const agent = await startAgent(process.env.RUNNER_TEMP || tmpdir());
  core.saveState('agent-pid', String(agent.pid));
  core.saveState('agent-dir', agent.dir);
  await addCertificate(agent.socket, { seed, pub, certBlob: cert.blob, comment, lifetime });
  seed.fill(0);

  core.exportVariable('SSH_AUTH_SOCK', agent.socket);
  core.exportVariable('SSH_AGENT_PID', String(agent.pid));
  core.setOutput('ssh-auth-sock', agent.socket);
  core.setOutput('certificate', certificate);
  core.setOutput('public-key', publicKey);

  const until = new Date(Number(cert.validBefore) * 1000).toISOString();
  core.info(`Signed ${cert.keyId} for ${cert.principals.join(', ') || '(no principals)'}, valid until ${until}`);
  core.info(`Loaded into ssh-agent at ${agent.socket} (SSH_AUTH_SOCK); the key never touched the disk`);
}

run().catch((error) => core.setFailed(error.message));
