# sasteval

**WARNING: This repository contains intentionally vulnerable code.**

This repo contains known-bad code including SQL injection, XSS, path traversal, SSRF,
unsafe deserialization, auth bypass, hardcoded secrets, and vulnerable dependencies.
Do not deploy this to any server. Do not run this in any environment you care about.
This is a static scanning target, not an application. Running it exposes you to RCE,
data exfiltration, and account takeover.

---

## What it is

sasteval is a ground-truth benchmark for evaluating SAST and SCA scanners. Point your
scanner at the source or compiled artifacts and compare findings against the documented
vulnerability catalog.

It is not a training app like WebGoat or DVWA. There is no web UI to log into.
Scan it and compare results.

- Every finding maps to a CWE ID, file, and line number
- Three taint-flow difficulty tiers: easy (same-function), medium (cross-method), hard (cross-file)
- 30 false-positive seeds: secure patterns using the same dangerous APIs as the vulnerable counterparts
- AI-legacy tier: patterns commonly introduced by LLM-generated code
- SCA reachability pairs: one reachable CVE, one unreachable, per language
- 106 total findings across Java and .NET

## Directory structure

```
sasteval/
├── README.md
├── LICENSE
├── VULNERABILITIES.md         # Full finding catalog
├── VERACODE.md                # Veracode upload instructions
├── java/                      # Java (Maven) benchmark module
│   ├── pom.xml
│   └── src/main/java/com/sasteval/
│       ├── vuln/easy/         # Direct taint (CWE-89, CWE-79, ...)
│       ├── vuln/medium/       # Cross-method taint
│       ├── vuln/hard/         # Cross-file taint chains
│       ├── vuln/ailegacy/     # LLM-generated mistake patterns
│       ├── safe/              # True-negative seeds
│       ├── sca/               # SCA reachability demos
│       └── util/
├── dotnet/                    # .NET (C#) benchmark module
│   ├── SastEval.sln
│   ├── SastEval.csproj
│   └── ...                    # Mirrors Java structure
├── ground-truth/
│   ├── expectedresults.csv         # 106 findings: CWE, file, line, severity, tier
│   └── expectedresults.strict.csv  # Core taint findings only
├── veracode/                  # Pre-built artifacts for Veracode Upload and Scan
│   ├── sasteval-java-1.0.0.war
│   └── sasteval-dotnet-net8-debug.zip
├── results/
│   └── free-scanners/         # Semgrep, SpotBugs, Trivy reference output
├── scripts/
│   ├── build-java.sh
│   ├── build-dotnet.sh
│   └── package-veracode.sh
└── docs/
    ├── manual-review-report.md
    ├── manual-review-checklist.md
    └── tooling-validation.md
```

## Scanning (source-level)

Point your scanner at the repo root or a language directory:

```bash
semgrep scan --sarif -o results.sarif java/
snyk code test java/ --sarif-file-output=results.sarif
codeql database create db --language=java --source-root=java/
```

GitLab SAST and Dependency Scanning run automatically on push via `.gitlab-ci.yml`.

## Veracode

Pre-built artifacts are included. No local Java or .NET installation required.

- `veracode/sasteval-java-1.0.0.war`
- `veracode/sasteval-dotnet-net8-debug.zip`

Upload each as a separate Veracode application profile. See [VERACODE.md](VERACODE.md) for
the full walkthrough.

## Comparing results

After scanning, compare output against `ground-truth/expectedresults.csv`.

For notes on which findings are strong cross-tool signals and which are business-logic
dependent, see [docs/tooling-validation.md](docs/tooling-validation.md).

For justification of every individual finding, see [docs/manual-review-report.md](docs/manual-review-report.md).

## Disclaimer

This repository is provided for security research and scanner evaluation only.
The vulnerabilities are intentional and documented. Do not use this code in any
production system or deploy it to any accessible network. The authors are not
responsible for any damage caused by misuse of this repository.

## License

MIT - see [LICENSE](LICENSE).
