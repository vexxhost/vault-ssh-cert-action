// The runner's public IPv4 address, for binding a certificate to it.
import got from 'got';
import { isIPv4 } from 'node:net';

// GitHub-hosted runners are Azure VMs without a public address of their own:
// they go out through a load balancer, whose outbound address Azure's
// instance metadata service reports.
export const IMDS_URL = 'http://169.254.169.254/metadata/loadbalancer?api-version=2021-02-01';
// Elsewhere (self-hosted runners), ask Cloudflare's echo service.
export const ECHO_URL = 'https://ipv4.icanhazip.com';

const options = { timeout: { request: 5_000 }, retry: { limit: 0 } };

export async function fromImds(url = IMDS_URL) {
  const { body } = await got(url, { ...options, headers: { Metadata: 'true' }, responseType: 'json' });
  const addresses = [...new Set((body?.loadbalancer?.outboundRules ?? []).map((rule) => rule.frontendIpAddress))];
  if (addresses.length !== 1 || !isIPv4(addresses[0])) {
    throw new Error(`expected one outbound IPv4 address, got ${JSON.stringify(addresses)}`);
  }
  return addresses[0];
}

export async function fromEcho(url = ECHO_URL) {
  const address = (await got(url, options).text()).trim();
  if (!isIPv4(address)) {
    throw new Error(`not an IPv4 address: ${JSON.stringify(address.slice(0, 64))}`);
  }
  return address;
}

// Returns { address, source }; throws if no source answers.
export async function publicIp({ imdsUrl = IMDS_URL, echoUrl = ECHO_URL } = {}) {
  const errors = [];
  for (const [source, lookup] of [['Azure instance metadata', () => fromImds(imdsUrl)], [echoUrl, () => fromEcho(echoUrl)]]) {
    try {
      return { address: await lookup(), source };
    } catch (error) {
      errors.push(`${source}: ${error.message}`);
    }
  }
  throw new Error(`could not find the runner's public IP (${errors.join('; ')})`);
}
