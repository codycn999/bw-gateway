#!/usr/bin/env python3
"""Create a gateway key for one agent.

Usage (on any machine with python3, ideally the VM itself):
    python3 scripts/new-agent-key.py cody 'OPENAI_*,GITHUB_TOKEN'
    python3 scripts/new-agent-key.py ci 'project:<project-uuid>'
    python3 scripts/new-agent-key.py deployer '<secret-uuid>,<secret-uuid>'

Prints two things:
  1. the line to append to /etc/bw-gateway/env (only the hash is stored there)
  2. the key itself, to hand to the agent once; it is not stored anywhere
"""
import hashlib
import re
import secrets
import sys


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    name, allow = sys.argv[1], sys.argv[2]
    if not re.fullmatch(r"[A-Za-z0-9_]+", name):
        sys.exit("agent name may contain only letters, digits and _")
    patterns = [p.strip() for p in allow.split(",") if p.strip()]
    if not patterns:
        sys.exit("give at least one secret name, glob, secret uuid or project:<uuid>")
    if "*" in patterns:
        print("warning: '*' lets this agent read every secret", file=sys.stderr)
    key = "bwg_" + secrets.token_urlsafe(32)
    digest = hashlib.sha256(key.encode()).hexdigest()
    print("# 1) append to /etc/bw-gateway/env, then: sudo systemctl restart bw-gateway")
    print("GATEWAY_KEY_%s=%s:%s" % (name.upper(), digest, ",".join(patterns)))
    print()
    print("# 2) give this key to the agent (shown once, not stored):")
    print(key)


if __name__ == "__main__":
    main()
