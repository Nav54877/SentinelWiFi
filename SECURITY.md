# Security Policy

## Scope

SentinelWiFi is a passive, defensive auditor. It is designed to be safe to
run on untrusted networks: it never injects frames, never attempts
authentication, never leaves the local subnet, and stores all data in
`~/.sentinelwifi/` on the machine running it. There is no telemetry, no
cloud component, and no auto-update mechanism.

## What we consider a vulnerability

- Anything that transmits data off the machine or to a third party
- Anything that sends traffic outside the local subnet
- Any capability whose purpose is accessing a network without
  authorization (injection, deauthentication, credential attacks)
- Local privilege issues: the tool should never need more than the
  documented privileges (root/Administrator for sniffing and ARP)

If you find behavior that violates the above, please report it — that is
exactly the class of bug we care most about.

## Reporting

Open an issue at
https://github.com/Nav54877/SentinelWiFi/issues and label it
`security`, or email the maintainer via the address on their GitHub
profile. Please include:

- the command you ran and its output
- OS, Python version, and adapter type
- whether scapy was installed and whether you used sudo

Please do **not** open a public issue containing packet captures from
networks you do not own.
