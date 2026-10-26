// Runs at the end of the job, even after failures: forget the key, stop the
// agent and revoke the Vault token.
import * as core from '@actions/core';
import { join } from 'node:path';

import { connection } from './inputs.js';
import { removeAllIdentities, stopAgent } from './ssh.js';
import { revokeToken } from './vault.js';

async function run() {
  const pid = Number(core.getState('agent-pid')) || undefined;
  const dir = core.getState('agent-dir');
  if (dir) {
    try {
      await removeAllIdentities(join(dir, 'agent.sock'));
    } catch (error) {
      core.debug(`removing the agent's identities: ${error.message}`);
    }
    stopAgent({ pid, dir });
    core.info('Stopped the ssh-agent and removed its socket');
  }

  if (core.getBooleanInput('revoke-token')) {
    const { url, token } = connection();
    if (url && token) {
      try {
        await revokeToken({ url, token });
        core.info('Revoked the Vault token');
      } catch (error) {
        core.warning(`could not revoke the Vault token: ${error.message}`);
      }
    }
  }
}

run().catch((error) => core.warning(error.message));
