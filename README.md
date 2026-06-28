# redforge-c2 — Authorized red-team engagement governance

[![CI](https://github.com/cognis-digital/redforge-c2/workflows/CI/badge.svg)](https://github.com/cognis-digital/redforge-c2/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Wrap an upstream C2 (Sliver/Mythic/Empire) with Rules of Engagement enforcement: scope, TPI, audit-log, expiration.


<!-- cognis:example:start -->
## 🔎 Example output

Real, reproducible output from the tool — runs offline:

```console
$ redforge-c2-emit --version
redforge-c2 0.1.0
```

```console
$ redforge-c2-emit --help
usage: redforge-c2 [-h] [--format {console,json,markdown,sarif,oscal}]
                   [--out OUT] [--fail-on {very_high,high,moderate,low,none}]
                   [--classification CLASSIFICATION] [-v]
                   [target]

redforge-c2 — Cognis Digital · Military/IC ecosystem

positional arguments:
  target                Path/target

options:
  -h, --help            show this help message and exit
  --format {console,json,markdown,sarif,oscal}
  --out OUT             Write output to file
  --fail-on {very_high,high,moderate,low,none}
  --classification CLASSIFICATION
                        Operator-supplied banner. PLACEHOLDER. Tool does not
                        interpret.
  -v, --version         show program's version number and exit
```

> Blocks above are real `redforge-c2` output — reproduce them from a clone.

<!-- cognis:example:end -->

## Usage — step by step

`redforge-c2` is an engagement-governance overlay for *authorized* red-team C2: it scans a session/audit log for rules-of-engagement (ROE) violations.

1. **Install:**

   ```bash
   pip install cognis-redforge-c2      # or: pip install -e .
   redforge-c2 --version
   ```

2. **Run a scan** over the engagement workspace (must contain the session audit log; `target` defaults to `.`):

   ```bash
   redforge-c2 ./engagement --format console
   ```

3. **Emit JSON** and save it (formats: `console`, `json`, `markdown`, `sarif`, `oscal`):

   ```bash
   redforge-c2 ./engagement --format json --out roe-findings.json
   ```

4. **Read the result** — findings flag a missing log (`RF-NOLOG`), denied actions (`RF-DENY`), and missing two-person-integrity approval (`RF-TPI-MISS`, very high):

   ```bash
   jq '.findings[] | {id, severity, message}' roe-findings.json
   ```

5. **Gate it in CI** — fail the pipeline on any very-high ROE violation:

   ```bash
   redforge-c2 ./engagement --format sarif --out redforge.sarif --fail-on very_high
   ```

## Upstream

Forks / wraps **https://github.com/BishopFox/sliver**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- ROE loader & validator (JSON)
- Pre-flight authorization on every command (scope/technique/window)
- TPI second-operator requirement on destructive ops
- Hash-chained audit log (use shared `cognis_mil.AuditLog`)
- Post-engagement compliance scanner (detects TPI gaps, scope violations)

## Install

```bash
# Shared library (only once for the whole ecosystem):
pip install -e ../../shared

# This tool:
pip install -e .
```

## Demo

```bash
redforge-c2 demos/
```

Outputs are available in five formats — all respect an operator-supplied
classification banner (passed via `--classification`):

```bash
redforge-c2 <target> --format=console     # default
redforge-c2 <target> --format=json
redforge-c2 <target> --format=sarif       # for code-scanning pipelines
redforge-c2 <target> --format=markdown    # for PRs / briefings
redforge-c2 <target> --format=oscal       # OSCAL Assessment Results skeleton
```

## Classification banner

All output is wrapped with an operator-supplied classification banner.
**Default**: `UNCLASSIFIED//FOR PUBLIC RELEASE`.

> ⚠️ This tool **does not** generate or validate the *content* of higher
> classifications. Operators on cleared systems supply real markings at runtime.
> See [`../shared/cognis_mil/classmark.py`](../../shared/cognis_mil/classmark.py).

## Compliance crosswalks (built in)

Every finding can carry references to:
- **NIST 800-53 Rev 5** controls (e.g. `AC-2(1)`)
- **DISA STIG** rule IDs (e.g. `V-242414`)
- **MITRE ATT&CK** technique IDs (e.g. `T1078`)
- **CCI** (Control Correlation Identifier)

These are emitted in JSON, SARIF, and the OSCAL skeleton.

## CI / RMF integration

```yaml
- name: redforge-c2 scan
  run: |
    pip install cognis-redforge-c2
    redforge-c2 . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

## Interoperability

`redforge-c2` composes with the 300+ tool Cognis suite — JSON in/out and a shared
OpenAI-compatible `/v1` backbone. See **[INTEROP.md](INTEROP.md)** for the
suite map, composition patterns, and reference stacks.

## Integrations

Forward `redforge-c2`'s findings to STIX/MISP/Sigma/Splunk/Elastic/Slack/webhooks via
[`cognis-connect`](https://github.com/cognis-digital/cognis-connect). See **[INTEGRATIONS.md](INTEGRATIONS.md)**.
