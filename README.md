# redforge-c2 — Authorized red-team engagement governance

[![CI](https://github.com/cognis-digital/redforge-c2/workflows/CI/badge.svg)](https://github.com/cognis-digital/redforge-c2/actions)
[![Classification](https://img.shields.io/badge/classification-UNCLASSIFIED-green.svg)](./UPSTREAM.md)

> Wrap an upstream C2 (Sliver/Mythic/Empire) with Rules of Engagement enforcement: scope, TPI, audit-log, expiration.

<!-- cognis:layman:start -->
## What is this?

redforge-c2 is a safety guardrail for authorized security testing teams — it sits in front of hacking tools like Sliver or Mythic and enforces the written rules before any command runs. Before a tester can touch a target system, the tool checks that the target is on the approved list, the technique is permitted, the time window is active, and — for risky actions like deleting files — that a second operator has also approved it. Every decision is recorded in a tamper-evident audit log, and after a test is complete you can run a compliance scan to catch any gaps, such as a destructive action that bypassed the two-person approval requirement. It is aimed at military and government red teams that need documented, auditable proof they stayed within their authorization.
<!-- cognis:layman:end -->

## Upstream

Forks / wraps **https://github.com/BishopFox/sliver**. See [`UPSTREAM.md`](./UPSTREAM.md) for the
licensing posture, supported commits, and how to upgrade.

## What this adds for military / IC use

- ROE loader & validator (JSON)
- Pre-flight authorization on every command (scope/technique/window)
- TPI second-operator requirement on destructive ops
- Hash-chained audit log (use shared `cognis_mil.AuditLog`)
- Post-engagement compliance scanner (detects TPI gaps, scope violations)

<!-- cognis:domains:start -->
## Domains

**Primary domain:** Cyber & Security  ·  **JTF MERIDIAN division:** NULLBYTE · SPECTER

**Topics:** `cognis` `security` `infosec` `cybersecurity` `blue-team`

Part of the **Cognis Neural Suite** — 300+ source-available tools organized across 12 domains under the JTF MERIDIAN command structure. See the [suite on GitHub](https://github.com/cognis-digital) and [jtf-meridian](https://github.com/cognis-digital/jtf-meridian) for how the pieces fit together.
<!-- cognis:domains:end -->

<!-- cognis:install:start -->
## Install

`redforge-c2` is source-available (not published to PyPI) — every method below installs
straight from GitHub. Pick whichever you prefer; the one-line scripts auto-detect
the best tool available on your machine.

**One-liner (Linux / macOS):**
```sh
curl -fsSL https://raw.githubusercontent.com/cognis-digital/redforge-c2/HEAD/install.sh | sh
```

**One-liner (Windows PowerShell):**
```powershell
irm https://raw.githubusercontent.com/cognis-digital/redforge-c2/HEAD/install.ps1 | iex
```

**Or install manually — any one of:**
```sh
pipx install "git+https://github.com/cognis-digital/redforge-c2.git"     # isolated (recommended)
uv tool install "git+https://github.com/cognis-digital/redforge-c2.git"  # uv
pip install "git+https://github.com/cognis-digital/redforge-c2.git"      # pip
```

**From source:**
```sh
git clone https://github.com/cognis-digital/redforge-c2.git
cd redforge-c2 && pip install .
```

Then run:
```sh
redforge-c2 --help
```
<!-- cognis:install:end -->

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
    pip install "git+https://github.com/cognis-digital/redforge-c2.git"
    redforge-c2 . --format=oscal --out=assessment-results.json --fail-on=high
- name: Upload to eMASS/Xacta
  run: cognis-rmf-package import assessment-results.json
```

## Part of the Cognis Digital military / IC ecosystem

12 repos. All MIT/Apache-2.0/GPL-3 (per upstream). Cognis additions are
Apache-2.0 unless stated otherwise.

See [the master index](../../MASTER-INDEX.md).

<a name="verification"></a>
## Verification

[![tests](https://img.shields.io/badge/tests-5%20passing-2ea44f.svg)](AUDIT.md)

Every push is verified end-to-end. Latest audit (2026-06-13):

```text
tests        : 5 passed, 0 failed, 0 errored
compile      : all modules parse
cli          : redforge-c2 0.1.0
package      : redforge_c2
```

<details><summary>CLI surface (<code>--help</code>)</summary>

```text
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
```
</details>

Full machine-readable results: [`AUDIT.md`](AUDIT.md) · regenerate with `python -m redforge_c2 --help` + `pytest -q`.

<div align="right"><a href="#top">↑ back to top</a></div>

