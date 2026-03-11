# Tooling Validation Notes

This note is for using `sasteval` as a fidelity benchmark between SAST and SCA tools.
It separates high-signal benchmark cases from findings that are legitimate but less
stable across tools, and it documents the current SCA mismatches.

## Recommended Scoring Sets

### Core SAST set

These categories are strong cross-tool signals and are appropriate for primary
fidelity scoring:

- CWE-22 path traversal
- CWE-78 command injection
- CWE-79 reflected and stored XSS
- CWE-89 SQL injection
- CWE-90 LDAP injection
- CWE-117 log injection
- CWE-209 error information leak
- CWE-295 improper certificate validation
- CWE-327 weak cipher / broken crypto
- CWE-328 weak hashing
- CWE-330 insecure randomness
- CWE-502 unsafe deserialization
- CWE-598 sensitive token in URL
- CWE-601 open redirect
- CWE-611 XXE
- CWE-614 insecure cookie flags
- CWE-643 XPath injection
- CWE-798 hardcoded secrets
- CWE-918 SSRF
- CWE-1333 regex DoS

These findings are explicit in source, have a concrete sink or dangerous API, and are
the most likely to produce meaningful SAST-vs-SAST comparisons.

### Extended SAST set

These findings are real or security-relevant, but they are weaker as benchmark truth
for cross-tool fidelity because they depend on business logic, policy modeling, or
availability-only interpretation:

- CWE-639 IDOR in `IdorController` for both languages
  Reason: real authorization flaw with a clearer sink now, but still more business-logic
  dependent than classic taint vulnerabilities.
- CWE-306 auth bypass in `AuthBypass` for both languages
  Reason: stronger than before because it now reaches a destructive sink, but still depends
  on intended authorization semantics.
- CWE-129 unvalidated array index in `UnvalidatedArrayIndex` for both languages
  Reason: real issue in this corpus because user input selects privileged internal actions,
  but still more dispatch and business-logic driven than classic taint-to-sink flaws.
- CWE-312 cleartext storage in `CleartextStorageDirect` for both languages
  Reason: legitimate security/compliance issue, but tool coverage is often policy-driven
  rather than taint-driven, so expect inconsistent SAST support.
- CWE-501 trust-boundary poisoning in `TrustBoundaryViolation` for both languages
  Reason: real privilege issue, but it depends on state semantics and authorization logic
  rather than a standard dangerous API sink.
- CWE-754 exceptional-condition bypass in `NullCheckBypass` for both languages
  Reason: real fail-open authorization flaw, but it is path- and error-handling dependent
  rather than a stable source/sink pattern.

Recommendation: keep these examples in the corpus, but score them separately from the
core SAST set if you want clean tool-to-tool fidelity numbers.

## Findings To Rework Or Remove For Strict Source/Sink Evaluation

If you want a corpus that follows GitLab Advanced SAST's published preference for
verifiable HTTP-source to sensitive-sink flows, these are the main remaining cases to
score separately or rework further:

- `SAST-JAVA-007`
  Reason: now uses a cleaner sink, but remains business-logic based.
- `SAST-JAVA-008`
  Reason: now uses a cleaner sink, but remains business-logic based.
- `SAST-DOTNET-007`
  Reason: now uses a cleaner sink, but remains business-logic based.
- `SAST-DOTNET-008`
  Reason: now uses a cleaner sink, but remains business-logic based.
- `SAST-JAVA-009`
  Reason: privileged delete is gated by a client-controlled admin flag and depends on
  intended authorization semantics rather than a classic dangerous API sink.
- `SAST-DOTNET-009`
  Reason: privileged delete is gated by a client-controlled admin flag and depends on
  intended authorization semantics rather than a classic dangerous API sink.
- `SAST-JAVA-032`
  Reason: null-triggered fail-open authorization is real, but error-path semantics make it
  less stable as a strict source/sink benchmark.
- `SAST-DOTNET-032`
  Reason: null-triggered fail-open authorization is real, but error-path semantics make it
  less stable as a strict source/sink benchmark.
- `SAST-JAVA-033`
  Reason: user-controlled role poisoning of session state is real, but depends on trusted
  state modeling more than a standard dangerous sink.
- `SAST-DOTNET-033`
  Reason: user-controlled role poisoning of session state is real, but depends on trusted
  state modeling more than a standard dangerous sink.
- `SAST-JAVA-034`
  Reason: attacker-controlled action selection is real, but it is dispatch-driven and more
  context-heavy than classic injection classes.
- `SAST-DOTNET-034`
  Reason: attacker-controlled action selection is real, but it is dispatch-driven and more
  context-heavy than classic injection classes.
- `SCA-DOTNET-001`
  Reason: current code loads a project file, but does not hit the advisory's documented
  vulnerable condition and should not be used as a reachable SCA truth case.

Second-pass candidates to score separately:

- `SAST-JAVA-020` and `SAST-DOTNET-020`
  Reason: real security/compliance issue, but not a taint-style exploit sink.
- `SAST-JAVA-022`, `SAST-JAVA-036`, `SAST-DOTNET-022`, and `SAST-DOTNET-036`
  Reason: legitimate web-security issues, but typically detected by rule-based policy
  checks rather than deeper source/sink reasoning.

## True Negative Seeds

The 30 TN seeds are appropriate for precision testing. In particular:

- `SafeSqlQuery` and `SafeHtmlOutput` are strong sanitization/parameterization checks.
- `InternalDataQuery` is a useful test for distinguishing internal constants from user input.
- `DeadCodeVuln` is intentionally harder: some tools will still report it because they
  do not suppress unreachable private code. Treat this as a precision stress test, not
  as a universal expectation.
- `SafePathTraversal`, `SafeSsrfAllowlist`, `SafeIdorOwnershipCheck`, `SafeAuthzFromSession`,
  and `SafeRegexAllowlist` are near-miss honeypots: they intentionally preserve the dangerous
  API shape while adding a visibly effective control.

## SCA Validation

### SCA-JAVA-001

- Package/version: `logback-core:1.5.6`
- Advisory: `CVE-2024-12798`
- Status: legitimate vulnerable dependency
- Reachability note: the benchmark calls `JoranConfigurator.doConfigure(...)` with a
  user-controlled path. That is a reasonable reachability signal, but exploitability still
  depends on the attacker controlling the referenced config content/path.

### SCA-JAVA-002

- Package/version: `lz4-java:1.8.0`
- Advisory: `CVE-2025-12183`
- Status: legitimate vulnerable dependency
- Reachability note: current sample imports lz4 only and never calls into the library,
  so this should stay `UNREACHABLE`.

### SCA-DOTNET-001

- Package/version: `Microsoft.Build:17.14.8`
- Advisory: `CVE-2025-55247`
- Status: real package advisory, but the current benchmark claim is not faithful
- Problem: the sample uses `new Project(projectPath)`, while the advisory condition is
  documented around `DownloadFile` task behavior on Linux with temporary directories.
- Recommendation: do not score this as `REACHABLE` until the sample is replaced with a
  call path that actually exercises the documented vulnerable condition.

### SCA-DOTNET-002

- Package/version: `NuGet.Packaging:6.8.0`
- Correct advisory: `CVE-2024-0057 / GHSA-68w7-72jg-6qpp`
- Status: real package advisory, current benchmark metadata was mislabeled
- Reachability note: the current sample only imports the namespace and does not invoke
  NuGet.Packaging APIs, so this should stay `UNREACHABLE`.
