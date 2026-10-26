// SSH wire format, ed25519 keys and certificates, and a minimal ssh-agent
// client: enough to load a certificate into an agent without it ever
// touching the disk.
import { spawn } from 'node:child_process';
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createConnection } from 'node:net';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

export const KEY_TYPE = 'ssh-ed25519';
export const CERT_TYPE = 'ssh-ed25519-cert-v01@openssh.com';

// Agent protocol (draft-ietf-sshm-ssh-agent).
const AGENT_FAILURE = 5;
const AGENT_SUCCESS = 6;
const AGENTC_REMOVE_ALL_IDENTITIES = 19;
const AGENTC_ADD_ID_CONSTRAINED = 25;
const CONSTRAIN_LIFETIME = 1;

export function string(value) {
  const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  return Buffer.concat([length, data]);
}

function uint32(value) {
  const data = Buffer.alloc(4);
  data.writeUInt32BE(value);
  return data;
}

class Reader {
  constructor(data) {
    this.data = data;
    this.offset = 0;
  }

  take(length) {
    if (this.offset + length > this.data.length) {
      throw new Error('truncated SSH data');
    }
    const value = this.data.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  uint32() {
    return this.take(4).readUInt32BE();
  }

  uint64() {
    return this.take(8).readBigUInt64BE();
  }

  string() {
    return this.take(this.uint32());
  }
}

// A fresh ed25519 key pair, in memory only. seed is the 32-byte private key.
export function generateKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pub = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url');
  const seed = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  return { pub, seed };
}

// The OpenSSH public key line for an ed25519 public key.
export function publicKeyLine(pub, comment = '') {
  const blob = Buffer.concat([string(KEY_TYPE), string(pub)]);
  return `${KEY_TYPE} ${blob.toString('base64')}${comment ? ` ${comment}` : ''}`;
}

// Parse an OpenSSH ed25519 certificate line ("ssh-ed25519-cert-v01@openssh.com
// AAAA... [comment]").
export function parseCertificate(line) {
  const [type, base64] = line.trim().split(/\s+/);
  if (type !== CERT_TYPE || !base64) {
    throw new Error(`not an ${CERT_TYPE} certificate`);
  }
  const blob = Buffer.from(base64, 'base64');
  const r = new Reader(blob);
  if (r.string().toString() !== CERT_TYPE) {
    throw new Error('certificate type does not match its encoding');
  }
  r.string(); // nonce
  const pub = r.string();
  const serial = r.uint64();
  const certType = r.uint32();
  const keyId = r.string().toString();
  const principalsReader = new Reader(r.string());
  const principals = [];
  while (principalsReader.offset < principalsReader.data.length) {
    principals.push(principalsReader.string().toString());
  }
  const validAfter = r.uint64();
  const validBefore = r.uint64();
  return { blob, pub, serial, certType, keyId, principals, validAfter, validBefore };
}

// Start a private ssh-agent with its socket in a new directory under parent
// (mode 0700). The caller stops it with stopAgent.
export async function startAgent(parent) {
  const dir = mkdtempSync(join(parent, 'vault-ssh-cert-'));
  const socket = join(dir, 'agent.sock');
  const child = spawn('ssh-agent', ['-D', '-a', socket], { detached: true, stdio: 'ignore' });
  child.unref();
  for (let i = 0; i < 50 && !existsSync(socket); i++) {
    if (child.exitCode !== null) {
      break;
    }
    await sleep(100);
  }
  if (!existsSync(socket)) {
    stopAgent({ pid: child.pid, dir });
    throw new Error('ssh-agent did not start');
  }
  return { pid: child.pid, dir, socket };
}

// Stop an agent started by startAgent and remove its directory. Safe to call
// more than once.
export function stopAgent({ pid, dir }) {
  if (pid) {
    try {
      process.kill(pid, 'SIGTERM');
    } catch (error) {
      if (error.code !== 'ESRCH') {
        throw error;
      }
    }
  }
  if (dir) {
    rmSync(dir, { recursive: true, force: true });
  }
}

// Send one agent request and return the response payload (type byte first).
export function agentRequest(socket, payload) {
  return new Promise((resolve, reject) => {
    const conn = createConnection(socket);
    let data = Buffer.alloc(0);
    conn.on('connect', () => conn.write(string(payload)));
    conn.on('data', (chunk) => {
      data = Buffer.concat([data, chunk]);
      if (data.length >= 4 && data.length >= 4 + data.readUInt32BE(0)) {
        conn.end();
        resolve(data.subarray(4, 4 + data.readUInt32BE(0)));
      }
    });
    conn.on('error', reject);
    conn.on('close', () => reject(new Error('ssh-agent closed the connection')));
  });
}

async function expectSuccess(socket, payload, what) {
  const response = await agentRequest(socket, payload);
  if (response[0] !== AGENT_SUCCESS) {
    throw new Error(`ssh-agent refused to ${what} (${response[0] === AGENT_FAILURE ? 'failure' : `reply ${response[0]}`})`);
  }
}

// Load an ed25519 private key with its certificate, for lifetime seconds.
export function addCertificate(socket, { seed, pub, certBlob, comment, lifetime }) {
  const payload = Buffer.concat([
    Buffer.from([AGENTC_ADD_ID_CONSTRAINED]),
    string(CERT_TYPE),
    string(certBlob),
    string(pub),
    string(Buffer.concat([seed, pub])),
    string(comment),
    Buffer.from([CONSTRAIN_LIFETIME]),
    uint32(lifetime),
  ]);
  return expectSuccess(socket, payload, 'add the certificate');
}

export function removeAllIdentities(socket) {
  return expectSuccess(socket, Buffer.from([AGENTC_REMOVE_ALL_IDENTITIES]), 'remove its identities');
}
