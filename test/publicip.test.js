import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { after, before, describe, it } from 'node:test';

import { fromEcho, fromImds, publicIp } from '../src/publicip.js';

describe('publicip', () => {
  let server;
  let base;
  const seen = [];

  before(async () => {
    server = createServer((req, res) => {
      seen.push({ url: req.url, metadata: req.headers.metadata });
      const routes = {
        '/imds': () => (req.headers.metadata === 'true'
          ? JSON.stringify({ loadbalancer: { outboundRules: [
            { frontendIpAddress: '20.161.67.214', privateIpAddress: '10.1.1.152' },
            { frontendIpAddress: '20.161.67.214', privateIpAddress: '10.1.1.152' },
          ] } })
          : null),
        '/imds-two': () => JSON.stringify({ loadbalancer: { outboundRules: [
          { frontendIpAddress: '20.0.0.1' }, { frontendIpAddress: '20.0.0.2' }] } }),
        '/imds-none': () => JSON.stringify({ loadbalancer: { outboundRules: [] } }),
        '/echo': () => '203.0.113.7\n',
        '/echo-v6': () => '2001:db8::1\n',
        '/echo-html': () => '<html>nope</html>',
      };
      const body = routes[req.url]?.();
      if (body == null) {
        res.statusCode = 400;
        res.end('bad request');
        return;
      }
      res.end(body);
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${server.address().port}`;
  });
  after(() => server.close());

  it('reads the load balancer outbound address from IMDS', async () => {
    seen.length = 0;
    assert.equal(await fromImds(`${base}/imds`), '20.161.67.214');
    assert.equal(seen[0].metadata, 'true');
  });

  it('rejects ambiguous or missing IMDS answers', async () => {
    await assert.rejects(fromImds(`${base}/imds-two`), /expected one outbound IPv4 address/);
    await assert.rejects(fromImds(`${base}/imds-none`), /expected one outbound IPv4 address/);
  });

  it('validates echo answers', async () => {
    assert.equal(await fromEcho(`${base}/echo`), '203.0.113.7');
    await assert.rejects(fromEcho(`${base}/echo-v6`), /not an IPv4 address/);
    await assert.rejects(fromEcho(`${base}/echo-html`), /not an IPv4 address/);
  });

  it('prefers IMDS, falls back to the echo service, and fails if both do', async () => {
    assert.deepEqual(await publicIp({ imdsUrl: `${base}/imds`, echoUrl: `${base}/echo` }),
      { address: '20.161.67.214', source: 'Azure instance metadata' });
    assert.deepEqual(await publicIp({ imdsUrl: 'http://127.0.0.1:1/', echoUrl: `${base}/echo` }),
      { address: '203.0.113.7', source: `${base}/echo` });
    await assert.rejects(publicIp({ imdsUrl: 'http://127.0.0.1:1/', echoUrl: `${base}/echo-html` }),
      /could not find the runner's public IP \(Azure instance metadata: .*; .*echo-html: not an IPv4 address/);
  });
});
