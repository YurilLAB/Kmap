# Connecting Kmap to ypanel

**ypanel** is Yuril Security's unified operator control panel — a single web app
(served at `https://yurillab.dev/ypanel`) for running the whole Yuril suite
(QPot, DireC, WEWAF, Kmap, GPTL) from one place, scoped to the licences an
operator owns. In ypanel, **Kmap** is the recon / attack-surface console:
dispatch scans, browse discovered hosts and services, and triage CVE/NSE
findings.

This document defines how Kmap connects to ypanel.

## The operator-plane model

Kmap is a CLI scanner (an nmap fork). ypanel does not run kmap in the browser —
it dispatches scan jobs to a **Kmap runner** (a host with kmap installed) through
the DireC **activation worker** (the operator plane), and ingests the structured
results.

```
  ypanel --scan job--> activation worker --job--> Kmap runner (kmap CLI)
  (browser)            (operator plane)           | runs the scan
       ^                                          v
       \---------- results (hosts/services/findings) <-- XML/JSON output
```

- A **scan job** carries the target (host / CIDR / hostname), profile
  (discovery / SYN / version / OS / aggressive), timing template (T0–T5), port
  spec, and NSE script categories — exactly the knobs ypanel's **New scan**
  launcher exposes.
- The **runner** executes `kmap` with the corresponding flags and returns the
  parsed output (`-oX`/`-oJ`). The operator plane stores it; ypanel renders
  scans, the host inventory (IP, PTR, OS fingerprint + accuracy, open ports,
  service+version), and findings (CVE cross-refs + NSE script results, CVSS
  graded).

### Safety + security model (load-bearing)

- **Authorised targets only.** Internet-scale scanning is legal and valuable for
  *your own* assets and authorised engagements (see this repo's README on
  Shodan/Censys/Project Sonar). A runner should enforce a target allowlist /
  scope file (`exclude.conf`) so the panel cannot dispatch out-of-scope scans.
- **Headers-only secrets** (operator session + client licence key); HTTPS
  enforced. The runner's host credentials never reach the browser.
- **Tenant isolation** (operators only see their own scans/assets) and an
  **allow-listed** job vocabulary (target + profile + timing — no arbitrary
  shell). **Fail-closed** reads.

## Status today (honest)

| Capability | Status |
|------------|--------|
| Kmap CLI: scanning, service/version detection, OS fingerprint, NSE, CVE engine | **implemented** (this repo) |
| ypanel Kmap section (Overview/Scans/Hosts/Findings/Settings) + scan launcher | **implemented** — honest demo today; scans are fully operable in demo |
| Operator-plane scan dispatch → Kmap runner + result ingest | **planned** — this doc defines the contract |

Until the runner + operator-plane dispatch are deployed, ypanel's Kmap screens
run on honest **Demo data** (you can launch a demo scan and watch it complete).
When the runner is live, the same launcher dispatches real jobs.
