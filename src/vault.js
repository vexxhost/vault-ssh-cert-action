// The two Vault/OpenBao calls this action makes, with got (as hashicorp/vault-action does).
import got from 'got';

function client(url, token) {
  return got.extend({
    prefixUrl: `${url.replace(/\/+$/, '')}/v1`,
    headers: { 'X-Vault-Token': token },
    responseType: 'json',
    timeout: { request: 30_000 },
    retry: { limit: 2, methods: ['POST'] },
  });
}

// Vault's own error message for a failed request.
export function describeError(error) {
  const errors = error.response?.body?.errors;
  if (Array.isArray(errors) && errors.length > 0) {
    return `HTTP ${error.response.statusCode}: ${errors.join('; ')}`;
  }
  return error.message;
}

// Sign publicKey (an OpenSSH public key line) with <sshPath>/sign/<role>.
export async function signKey({ url, token, sshPath, role, publicKey, principals, ttl }) {
  const path = `${sshPath.replace(/^\/+|\/+$/g, '')}/sign/${role}`;
  const json = { public_key: publicKey };
  if (principals) {
    json.valid_principals = principals;
  }
  if (ttl) {
    json.ttl = ttl;
  }
  let body;
  try {
    ({ body } = await client(url, token).post(path, { json }));
  } catch (error) {
    throw new Error(`POST ${path}: ${describeError(error)}`);
  }
  const signed = body?.data?.signed_key;
  if (typeof signed !== 'string' || !signed) {
    throw new Error(`POST ${path} returned no certificate`);
  }
  return signed.trim();
}

export async function revokeToken({ url, token }) {
  try {
    await client(url, token).post('auth/token/revoke-self');
  } catch (error) {
    throw new Error(`POST auth/token/revoke-self: ${describeError(error)}`);
  }
}
