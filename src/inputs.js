import * as core from '@actions/core';

// Inputs shared by main and post (inputs are passed to the post step too).
export function connection() {
  const url = core.getInput('url') || process.env.VAULT_ADDR || '';
  const token = core.getInput('token') || process.env.VAULT_TOKEN || '';
  if (token) {
    core.setSecret(token);
  }
  return { url, token };
}
