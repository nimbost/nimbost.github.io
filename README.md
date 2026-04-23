# ThreadT

ThreadT is a professional terminal reconnaissance project for **authorized** security assessments.

It prints a randomized ASCII intro logo each time it starts, performs multi-layer host intelligence collection, and writes a structured JSON report.

## Features

- Random ASCII intro logo on every run.
- DNS intelligence (A/AAAA + MX + NS where available).
- TLS certificate and transport metadata collection.
- HTTP metadata collection (status, headers, `robots.txt`, `sitemap.xml`).
- Certificate Transparency (crt.sh) subdomain discovery.
- Optional deep reconnaissance mode with common-port scanning.
- JSON output report for automation and collaboration.

## Quick start

```bash
python3 threadt.py --target example.com --authorized
```

Deep mode:

```bash
python3 threadt.py --target example.com --deep --authorized --output report.json
```

## Usage

```bash
python3 threadt.py --help
```

### Required confirmation

ThreadT requires `--authorized` to run. This project is intended for legal and approved testing.

## Typical workflow for a public GitHub project

1. Create a repository.
2. Commit `threadt.py` and this `README.md`.
3. Add a license (for example MIT).
4. Publish releases and accept community contributions.

## Disclaimer

Use this software only on assets you own or are explicitly permitted to assess.
