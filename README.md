# sasteval — SAST/SCA Security Benchmark

---

> **WARNING: THIS APPLICATION IS INTENTIONALLY VULNERABLE.**
>
> This repository contains code with **known security vulnerabilities** including
> SQL Injection, XSS, Path Traversal, SSRF, Unsafe Deserialization, IDOR,
> Authentication Bypass, Hardcoded Secrets, and vulnerable third-party dependencies.
>
> **NEVER deploy this application to any network-accessible server.**
> **NEVER use this code in production.**
>
> This is a **static scanning target only** — designed to be read by SAST/SCA tools,
> not executed by servers. Running this application exposes you to Remote Code
> Execution (RCE), data exfiltration, and account takeover.

---

## Purpose

sasteval is a ground-truth benchmark for evaluating Static Application Security
Testing (SAST) and Software Composition Analysis (SCA) scanners. Unlike training
applications (WebGoat, DVWA), this project is a **passive scan target** — point your
scanner at the source or compiled artifacts and compare what it finds against the
documented vulnerability catalog.

- **Validated CWE mappings** — every vulnerability mapped to a CWE ID, file, and line number
- **Difficulty stratification** — easy (same-function), medium (cross-method), and hard (cross-file) taint flows
- **False-positive seeds** — secure patterns that mimic vulnerabilities to measure scanner precision
- **AI-mistake simulation** — common LLM coding errors (auth bypass, weak hashing, hardcoded secrets)
- **SCA reachability testing** — both reachable and unreachable vulnerable dependencies
- **Deterministic results** — no race conditions or environment-dependent flaws

## Directory Structure

```
sasteval/
├── README.md                  # This file
├── LICENSE                    # Apache 2.0
├── VULNERABILITIES.md         # Complete listing of all intentional flaws
├── java/                      # Java (Maven) benchmark module
│   ├── pom.xml
│   └── src/main/java/com/sasteval/
│       ├── vuln/easy/         # CWE-89, CWE-79 (direct taint)
│       ├── vuln/medium/       # CWE-22, CWE-918 (cross-method)
│       ├── vuln/hard/         # CWE-502, CWE-639 (cross-file)
│       ├── vuln/ailegacy/     # AI-induced mistakes
│       ├── safe/              # False-positive seeds (true negatives)
│       ├── sca/               # SCA reachability demos
│       └── util/              # Shared DB and sanitizer utilities
├── dotnet/                    # .NET (C#) benchmark module
│   ├── SastEval.sln
│   ├── SastEval.csproj
│   └── ...                    # Mirrors Java structure
├── ground-truth/              # Expected findings catalog
│   ├── expectedresults.csv    # CWE, file, line, TP/TN mapping (all 96 findings)
│   └── expectedresults.strict.csv  # Core findings (excludes business-logic cases)
├── scripts/                   # Build helpers for binary-level scanners
│   ├── build-java.sh
│   └── build-dotnet.sh
└── docs/
    ├── manual-review-report.md     # Justification for every finding
    ├── manual-review-checklist.md  # Reviewer workflow template
    └── tooling-validation.md       # Cross-tool signal notes
```

## Scanning (Source-Level)

Point your SAST/SCA scanner at the repository root or individual language directories:

```bash
# Examples (substitute your scanner)
semgrep scan --sarif -o results.sarif java/
snyk code test java/ --sarif-file-output=results.sarif
codeql database create db --language=java --source-root=java/
```

## Veracode Upload Artifacts

This repo includes ready-to-upload artifacts in [veracode/README.md](veracode/README.md).
For the exact Veracode workflow and upload steps, see [VERACODE.md](VERACODE.md).
Users do not need to install Java, Maven, or .NET just to submit the benchmark to Veracode.

Use these files directly:

- `veracode/sasteval-java-1.0.0.war`
- `veracode/sasteval-dotnet-net8-debug.zip`

Upload them as separate Veracode application profiles for the cleanest module separation.

## Building (Binary-Level)

For maintainers who want to regenerate the packaged artifacts:

```bash
# Rebuilds Java and .NET artifacts and stages them under veracode/
./scripts/package-veracode.sh
```

## Comparing Results

After scanning, compare your tool's output against `ground-truth/expectedresults.csv`
which documents every intentional vulnerability and true-negative seed with CWE, file,
line number, severity, and difficulty tier.

For notes on which findings are strong cross-tool signals versus business-logic cases
that tools handle inconsistently, see [docs/tooling-validation.md](docs/tooling-validation.md).

For detailed justification of every finding, see [docs/manual-review-report.md](docs/manual-review-report.md).

## License

Apache 2.0 — see [LICENSE](LICENSE).
