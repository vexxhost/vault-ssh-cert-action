#!/usr/bin/env bash
# test/check.sh <principal>: the agent at SSH_AUTH_SOCK holds exactly one
# certificate, for exactly that principal, and it logs in to the test sshd.
set -euo pipefail
test "$(ssh-add -L | wc -l)" = 1
principals=$(ssh-add -L | ssh-keygen -L -f - | awk '/Principals:/ {p = 1; next} p && /^[[:space:]]+[^[:space:]]+$/ {print $1; next} {p = 0}')
test "$principals" = "$1"
ssh -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USER@127.0.0.1" true
