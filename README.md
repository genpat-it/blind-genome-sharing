# anonsurv: proof of concept

Food companies submit pathogen genomes (cgMLST profiles) **anonymously but with proof of
authorisation**. Public health clusters them with human cases and sends **private alerts** that
only the submitting company can read. No blockchain is needed: a database and a tamper-evident log suffice.

The protocol is explained step by step at the project page (`docs/index.html`, published with GitHub Pages).

**This is a proof of concept on synthetic data. It is not for production use.**

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py          # end-to-end scenario, about 10 s
.venv/bin/python -m pytest -q     # RFC 9474 test vectors + protocol tests
```

## Components

| Module | Role | Standard |
|---|---|---|
| `anonsurv/rsabssa.py` | RSA blind signatures, RSABSSA-SHA384-PSS(-ZERO), Randomized/Deterministic | RFC 9474, checked against its 4 test vectors |
| `anonsurv/issuer.py` | Checks the register, enforces a quota and blind-signs tokens. Records only how many tokens each company got | – |
| `anonsurv/client.py` | Company side. Generates tokens and blinding factors locally, unblinds, submits, reads alerts. Checks that the issuer key matches the published fingerprint (key-tagging defence) | – |
| `anonsurv/platform.py` | Verifies tokens with the issuer **public** key, rejects reused tokens, enforces the metadata policy. Stores no identity | – |
| `anonsurv/policy.py` | Metadata limited to species, month, NUTS region and food category. k-anonymity check, generalised ITF1 → ITF → IT | k-anonymity |
| `anonsurv/alerts.py` | One-time keys and encrypted alerts on a public bulletin | HPKE, RFC 9180 |
| `anonsurv/tlog.py` | Append-only hash chain. Any member holding the head detects rewriting | simplified RFC 9162 (no Merkle proofs) |
| `anonsurv/lab.py` | Allelic distance against clinical profiles, cluster threshold, sends alerts. cgDist can replace the distance | – |
| `anonsurv/synth.py` | Synthetic register (247 companies, 6 regions × 5 categories) and 1748-locus profiles | – |

## What the demo shows

1. Enrolment: 40 companies obtain 10 tokens each. The issuer ends up knowing only the counts.
2. 40 anonymous submissions. A company in a cell with only 2 companies is generalised to the macro-region.
3. Refusals: reused token, forged token, token signed with another key, exact date, unregistered company, quota exceeded.
4. Alerts: every company whose isolate belongs to an outbreak clone is alerted. No other company is, and nobody else can tell who was alerted.
5. Log: one silent rewrite of a record is detected against the head held by the members.

Measured on this machine (RSA-2048, in-process HTTP): about 20 ms per token (client + issuer) and
about 4 ms per submission.

## Not yet done

- Threshold identity escrow (Shamir / threshold decryption, t of n). Optional in the protocol.
- Network anonymity of submissions (Oblivious HTTP, RFC 9458), and batch issuance timing.
- Real data: NCBI Pathogen Detection profiles typed with chewBBACA; cgDist distances.
- Separate services (uvicorn + docker compose), real authentication (SPID/CIE) for the issuer.
- Merkle-tree log with inclusion proofs (Trillian / Rekor) and replication among members.

## Licence

Copyright © 2026 Istituto Zooprofilattico Sperimentale dell'Abruzzo e del Molise "G. Caporale".

Released under the European Union Public Licence v1.2 (EUPL-1.2); see `LICENSE`. All dependencies
are open source (cryptography: Apache-2.0/BSD; pyhpke, FastAPI: MIT; SQLite: public domain), and
the protocol uses only royalty-free open standards (RFC 8017, 9162, 9180, 9458, 9474).
