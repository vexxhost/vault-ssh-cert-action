import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { after, before, describe, it } from 'node:test';

import { revokeToken, signKey } from '../src/vault.js';

describe('vault', () => {
  let server;
  let url;
  const requests = [];

  before(async () => {
    server = createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        requests.push({ method: req.method, url: req.url, token: req.headers['x-vault-token'], body: body && JSON.parse(body) });
        res.setHeader('Content-Type', 'application/json');
        if (req.headers['x-vault-token'] !== 'good') {
          res.statusCode = 403;
          res.end(JSON.stringify({ errors: ['permission denied'] }));
        } else if (req.url === '/v1/ssh-client-signer/sign/deploy') {
          res.end(JSON.stringify({ data: { signed_key: 'ssh-ed25519-cert-v01@openssh.com AAAA\n' } }));
        } else if (req.url === '/v1/ssh-client-signer/sign/empty') {
          res.end(JSON.stringify({ data: {} }));
        } else if (req.url === '/v1/auth/token/revoke-self') {
          res.statusCode = 204;
          res.end();
        } else {
          res.statusCode = 400;
          res.end(JSON.stringify({ errors: ['unknown role', 'second'] }));
        }
      });
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    url = `http://127.0.0.1:${server.address().port}/`;
  });
  after(() => server.close());

  it('signs', async () => {
    requests.length = 0;
    const cert = await signKey({ url, token: 'good', sshPath: '/ssh-client-signer/', role: 'deploy',
      publicKey: 'ssh-ed25519 AAAA c', principals: 'deploy:a', ttl: '5m' });
    assert.equal(cert, 'ssh-ed25519-cert-v01@openssh.com AAAA');
    assert.deepEqual(requests, [{ method: 'POST', url: '/v1/ssh-client-signer/sign/deploy', token: 'good',
      body: { public_key: 'ssh-ed25519 AAAA c', valid_principals: 'deploy:a', ttl: '5m' } }]);
  });

  it('leaves out empty principals and ttl', async () => {
    requests.length = 0;
    await signKey({ url, token: 'good', sshPath: 'ssh-client-signer', role: 'deploy', publicKey: 'k', principals: '', ttl: '' });
    assert.deepEqual(requests[0].body, { public_key: 'k' });
  });

  it("reports Vault's errors", async () => {
    await assert.rejects(signKey({ url, token: 'bad', sshPath: 'ssh-client-signer', role: 'deploy', publicKey: 'k' }),
      /POST ssh-client-signer\/sign\/deploy: HTTP 403: permission denied/);
    await assert.rejects(signKey({ url, token: 'good', sshPath: 'ssh-client-signer', role: 'nope', publicKey: 'k' }),
      /HTTP 400: unknown role; second/);
    await assert.rejects(signKey({ url, token: 'good', sshPath: 'ssh-client-signer', role: 'empty', publicKey: 'k' }),
      /returned no certificate/);
  });

  it('revokes', async () => {
    requests.length = 0;
    await revokeToken({ url, token: 'good' });
    assert.deepEqual(requests.map((r) => r.url), ['/v1/auth/token/revoke-self']);
    await assert.rejects(revokeToken({ url, token: 'bad' }), /HTTP 403: permission denied/);
  });
});
