# Contributing

Thanks for taking a look. This project is deliberately small and
defensive; contributions that keep it that way are welcome.

## Ground rules

- **Passive only.** No injection, no deauthentication, no credential
  attacks, no offensive capability of any kind. CI enforces this with a
  grep over the package — if your change trips it, the change does not
  belong here.
- Every source file keeps the header: `For auditing networks you own or
  are authorized to test.`
- Test fixtures use generic synthetic data only. Never commit anything
  from a real network scan (SSIDs, BSSIDs, hostnames, outputs).
- The tool must degrade gracefully: a missing adapter, missing scapy, or
  missing monitor mode is a note in the report, never a crash.

## Development

```bash
pip install -r requirements.txt
python -m unittest discover -s tests
python sentinel.py selftest
```

Add a test for every bug fix — several of the current tests are
regressions from real-world runs, which is how this project likes to
work.

## Pull requests

Keep them small and focused. Update `CHANGELOG.md` under an
"Unreleased" heading if the change is user-visible. The CI matrix runs
3.10–3.12 and the honesty guards; make sure it stays green.
