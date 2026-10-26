import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, describe, it } from 'node:test';

import {
  addCertificate,
  generateKey,
  parseCertificate,
  publicKeyLine,
  removeAllIdentities,
  startAgent,
  stopAgent,
} from '../src/ssh.js';

// Have ssh-keygen sign pub with a throwaway CA, like Vault would.
function sign(parent, pub, principals, validity = '+10m') {
  const dir = mkdtempSync(join(parent, 'ca-'));
  execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', join(dir, 'ca')]);
  writeFileSync(join(dir, 'user.pub'), `${publicKeyLine(pub, 'test')}\n`);
  execFileSync('ssh-keygen', ['-q', '-s', join(dir, 'ca'), '-I', 'test-key', '-n', principals.join(','),
    '-V', validity, join(dir, 'user.pub')]);
  return readFileSync(join(dir, 'user-cert.pub'), 'utf8');
}

function agentList(socket) {
  try {
    return execFileSync('ssh-add', ['-L'], { env: { ...process.env, SSH_AUTH_SOCK: socket } }).toString();
  } catch (error) {
    return error.stdout.toString();
  }
}

describe('ssh', () => {
  let dir;
  before(() => {
    dir = mkdtempSync(join(tmpdir(), 'ssh-test-'));
  });
  after(() => rmSync(dir, { recursive: true, force: true }));

  it('writes public keys ssh-keygen accepts', () => {
    const { pub } = generateKey();
    writeFileSync(join(dir, 'k.pub'), `${publicKeyLine(pub, 'c')}\n`);
    assert.match(execFileSync('ssh-keygen', ['-l', '-f', join(dir, 'k.pub')]).toString(), /^256 SHA256:\S+ c \(ED25519\)/);
  });

  it('parses certificates', () => {
    const { pub } = generateKey();
    const cert = parseCertificate(sign(dir, pub, ['deploy:a', 'automation']));
    assert.ok(cert.pub.equals(pub));
    assert.equal(cert.keyId, 'test-key');
    assert.deepEqual(cert.principals, ['deploy:a', 'automation']);
    assert.equal(cert.certType, 1);
    const now = BigInt(Math.floor(Date.now() / 1000));
    assert.ok(cert.validBefore > now && cert.validBefore <= now + 601n);
  });

  it('rejects other key types', () => {
    assert.throws(() => parseCertificate('ssh-rsa AAAA'), /not an ssh-ed25519-cert/);
  });

  it('loads a certificate into an agent and cleans up', async () => {
    const { pub, seed } = generateKey();
    const line = sign(dir, pub, ['deploy:a']);
    const cert = parseCertificate(line);
    const agent = await startAgent(dir);
    try {
      await addCertificate(agent.socket, { seed, pub, certBlob: cert.blob, comment: 'test', lifetime: 600 });
      const listed = agentList(agent.socket);
      assert.equal(listed.trim().split(/\s+/)[1], line.trim().split(/\s+/)[1]);

      // The agent proves possession: it signs with the key it holds.
      const challenge = join(dir, 'challenge');
      writeFileSync(challenge, 'hello');
      writeFileSync(join(dir, 'agent-cert.pub'), listed);
      execFileSync('ssh-keygen', ['-Y', 'sign', '-n', 'test', '-f', join(dir, 'agent-cert.pub'), challenge],
        { env: { ...process.env, SSH_AUTH_SOCK: agent.socket }, stdio: 'ignore' });
      assert.ok(existsSync(`${challenge}.sig`));

      await removeAllIdentities(agent.socket);
      assert.match(agentList(agent.socket), /no identities/);
    } finally {
      stopAgent(agent);
    }
    assert.equal(existsSync(agent.dir), false);
    stopAgent(agent); // idempotent
  });
});
