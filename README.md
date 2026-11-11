# anonsurv: proof of concept

Food companies submit pathogen genomes (cgMLST profiles) **anonymously but with proof of
authorisation**. Public health clusters them with human cases and sends **private alerts** that
only the submitting company can read. No blockchain is needed: a database and a Merkle log
cosigned by the consortium members suffice.

- The protocol step by step: [project page](https://genpat-it.github.io/blind-genome-sharing/)
- Every message of a real run, animated: [the office](https://genpat-it.github.io/blind-genome-sharing/office.html)

**This is a proof of concept on synthetic data. It is not for production use.**

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py               # end-to-end scenario, all services in one process, ~20 s
.venv/bin/python -m pytest -q          # 217 tests, including the RFC test vectors
.venv/bin/python simulate.py --serve   # record a fresh run and watch it in the office
```

Every party as its own container (issuer, platform, OHTTP gateway and relay, three witnesses,
Keycloak as identity provider):

```bash
.venv/bin/python deploy/setup.py       # keys, register, Keycloak realm (deploy/config, git-ignored)
docker compose up -d --build
docker compose run --rm e2e            # companies, laboratory and trustees as network clients
docker compose down -v
```

## Components

| Module | Role | Standard, and how it is checked |
|---|---|---|
| `anonsurv/rsabssa.py` | RSA blind signatures, RSABSSA-SHA384-PSS(-ZERO), Randomized/Deterministic | RFC 9474; its 4 test vectors |
| `anonsurv/oidc.py`, `idp.py` | Company login. The issuer verifies the ID token and reads the VAT number (`https://attributes.eid.gov.it/vat_number`, as in SPID/CIE). `idp.py` is a demo provider; compose uses Keycloak | OpenID Connect Core |
| `anonsurv/issuer.py` | Checks the register, enforces a quota, blind-signs. With escrow, cut-and-choose: k = 8 sealed candidates per token, 7 opened and checked, 1 signed. Records only how many tokens each company got | – |
| `anonsurv/escrow.py` | Company identifier encrypted under a fresh key, key split t-of-n (Shamir) and sealed to each trustee with HPKE. Deterministic from a seed, so opened candidates can be rebuilt | Shamir; HPKE; Chaum–Fiat–Naor cut-and-choose |
| `anonsurv/client.py` | Company side: generates tokens, blinding factors and escrows locally, unblinds, submits, reads alerts, verifies receipts. Checks the issuer key, escrow trustees and gateway keys against the cosigned log entry 0 (no key tagging) | – |
| `anonsurv/ohttp.py`, `network.py` | Submissions go company → relay → gateway → platform. The relay sees who, not what; the gateway what, not who. `OhttpTransport` plugs into httpx | RFC 9458 + RFC 9292; the complete example of RFC 9458 Appendix A, byte for byte |
| `anonsurv/platform.py` | Verifies tokens with the issuer **public** key, rejects reused tokens and bad escrows, enforces the metadata policy, stores no identity. Logs disclosure requests | – |
| `anonsurv/tlog.py` | Merkle-tree log, signed tree heads, inclusion and consistency proofs. Each consortium member runs a witness that cosigns a head only if it extends the last one | RFC 9162; the 196 transparency-dev probes |
| `anonsurv/trustee.py` | Releases its escrow share only for a disclosure request that is in a cosigned head, and only if its people agree | – |
| `anonsurv/policy.py` | Metadata limited to species, month, NUTS region and food category. k-anonymity check, generalised ITF1 → ITF → IT | k-anonymity |
| `anonsurv/alerts.py` | One-time keys and encrypted alerts on a public bulletin | HPKE, RFC 9180 |
| `anonsurv/lab.py` | Allelic distance against clinical profiles, cluster threshold, sends alerts. cgDist can replace the distance | – |
| `anonsurv/world.py`, `serve.py` | The whole deployment in one process (tests, demo), or one service per process (compose) | – |
| `anonsurv/synth.py` | Synthetic register (247 companies, 6 regions × 5 categories) and 1748-locus profiles | – |

## What the demo shows

1. Enrolment: 40 companies log in and obtain 10 escrowed tokens each. The issuer ends up knowing only the counts.
   A company that hides another company's identifier in a candidate is caught 7 times in 8.
2. 40 anonymous submissions through the relay. A company in a cell with only 2 companies is generalised to the macro-region.
3. Refusals: reused token, forged token, token signed with another key, escrow of another token, exact date,
   forged ID token, company not in the register, quota exceeded, laboratory endpoints through the relay.
4. Alerts: every company whose isolate belongs to an outbreak clone is alerted. No other company is, and nobody else can tell who was alerted.
5. Log: companies check inclusion proofs of their records under a head cosigned by 3 witnesses. When the operator
   rewrites one entry, all witnesses refuse the next head and clients reject it.
6. Disclosure: no trustee acts before the request is in the cosigned log; then 3 of 5 shares reveal the submitter, 2 do not.

Measured on one core (RSA-2048, in-process HTTP, `bench.py`): about 20 ms per escrowed token (7 ms without escrow),
5 ms per submission directly and 12 ms through relay and gateway, 27 ms for a checkpoint cosigned by 3 witnesses.

## Real data (`analysis/`)

- `ncbi_lead_time.py`: NCBI Pathogen Detection, isolates 2015–2025. In 382 *L. monocytogenes* clusters (≤ 10 SNPs)
  with both human and food/environmental isolates, a non-human isolate came first in 44%, by a median of 22 months;
  in 42% a matching non-human genome was already public when the first human genome arrived; 43% of the human
  cases were collected after that moment.
- `anonymity_sets.py`: Eurostat counts of Italian food manufacturers. With k = 5 and 10% participation, at least 93%
  of companies in every sector except fish can report NUTS-2 region and sector.

## Limits

- Synthetic register and profiles in the protocol tests; the real-data analyses use public data that stand in for
  companies' own isolates and for the register of establishments.
- The demo identity provider and Keycloak stand in for SPID/CIE, which require accreditation of the issuer.
- Cut-and-choose makes the escrow sound except with probability 1/k per cheating attempt; anonymous credentials
  (BBS, Idemix) with verifiable encryption would make it exact.
- One log operator with witnesses (deployment model B); no replication of the database itself.

## Licence

Copyright © 2026 Istituto Zooprofilattico Sperimentale dell'Abruzzo e del Molise "G. Caporale".

Released under the European Union Public Licence v1.2 (EUPL-1.2); see `LICENSE`. All dependencies
are open source (cryptography: Apache-2.0/BSD; pyhpke, FastAPI, PyJWT: MIT; SQLite: public domain;
Keycloak: Apache-2.0), and the protocol uses only royalty-free open standards (RFC 8017, 9162, 9180,
9292, 9458, 9474; OpenID Connect). `tests/merkle_probes.json` is derived from the transparency-dev
test data (Apache-2.0).
