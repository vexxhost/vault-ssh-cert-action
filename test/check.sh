#!/usr/bin/env bash
# test/check.sh <principal>: KEY and CERT are a matching key and certificate
# for exactly that principal, and they log in to the test sshd.
set -euo pipefail
test "$CERT" = "$KEY-cert.pub"
principals=$(ssh-keygen -L -f "$CERT" | awk '/Principals:/ {p = 1; next} p && /^[[:space:]]+[^[:space:]]+$/ {print $1; next} {p = 0}')
test "$principals" = "$1"
ssh -i "$KEY" -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USER@127.0.0.1" true
