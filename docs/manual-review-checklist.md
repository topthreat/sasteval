# Manual Review Checklist

Use this template when reviewing a finding from the benchmark.

Goal:

- record what the code does
- record why the finding is or is not a real vulnerability
- make the review repeatable across reviewers

Reference:

- [manual-review-report.md](/home/tallenz/code/sasteval/docs/manual-review-report.md)
- [VULNERABILITIES.md](/home/tallenz/code/sasteval/VULNERABILITIES.md)
- [expectedresults.csv](/home/tallenz/code/sasteval/ground-truth/expectedresults.csv)

## Quick Triage

Reviewer:

Date:

Finding ID:

Language:

CWE:

File:

Line:

Category:

Tool that reported it:

Tier:

Initial expectation:

- `TP`
- `TN`
- `Unsure`

## Review Standard

For SAST, only confirm the finding if all are true:

- there is an attacker-controlled source
- there is a real dangerous sink or security-relevant decision
- there is no effective control in between
- the impact is plausible

For SCA, only confirm the finding if both are true:

- the dependency version is actually affected
- the application reaches the affected behavior, or clearly does not

## Evidence Block

Fill this out first.

```text
Source:
Sink:
Missing control:
Impact:
```

## SAST Checklist

Complete this section for SAST findings.

### 1. Source

- [ ] I identified the attacker-controlled input.
- [ ] The input comes from a real trust boundary such as query param, path param, form field, header, cookie, body, or stored attacker data.
- [ ] I traced the same value, or a directly derived value, forward through the code.

Notes:

### 2. Sink or Security Decision

- [ ] I identified the dangerous sink or authz decision point.
- [ ] The sink is real and security-relevant.
- [ ] The source reaches the sink or decision in the implemented code path.

Examples of real sinks:

- SQL execution
- HTML output
- command execution
- file read
- outbound server-side request
- XML parsing
- deserialization
- redirect
- authz decision on privileged action

Notes:

### 3. Control Check

- [ ] I checked for parameterization, output encoding, sanitizer use, allowlists, canonicalization, auth middleware, or other relevant controls.
- [ ] No effective control blocks exploitation in the reviewed path.
- [ ] If a control exists elsewhere, I verified whether it actually applies to this endpoint or method.

Notes:

### 4. Impact

- [ ] I can explain the security impact in one sentence.
- [ ] The impact is plausible without relying on unrealistic assumptions.

Impact sentence:

### 5. Verdict

- [ ] Confirmed TP
- [ ] Rejected as TP
- [ ] Context-dependent, escalate for senior review

Reason:

## SCA Checklist

Complete this section for SCA findings.

### 1. Affected Package

- [ ] I confirmed the package name.
- [ ] I confirmed the affected version is present.
- [ ] I checked the advisory identifier.

Package:

Version:

Advisory:

### 2. Reachability

- [ ] I identified whether the app calls the affected API or behavior.
- [ ] I compared the benchmark code to the advisory's documented condition.
- [ ] I determined one of: reachable, unreachable, package present only.

Relevant code path:

### 3. Verdict

- [ ] Reachable vulnerability
- [ ] Unreachable in this benchmark
- [ ] Package present, reachability not demonstrated
- [ ] Escalate for senior review

Reason:

## Category Prompts

Use the prompt that matches the finding.

### Injection

Ask:

- Did attacker input become executable syntax?

Look for:

- string concatenation into SQL, LDAP, XPath, command, or similar interpreter input

### XSS

Ask:

- Did attacker input become raw HTML or script-visible content in the response?

Look for:

- unencoded output
- raw interpolation into HTML
- stored user content rendered without sanitization

### File or Network Access

Ask:

- Did attacker input choose what file or URL the server accessed?

Look for:

- file read APIs
- URL fetch APIs
- missing allowlist or path validation

### XML or Deserialization

Ask:

- Did untrusted structured input reach a parser or deserializer with unsafe settings?

Look for:

- XXE-enabling parser settings
- `readObject()`
- `BinaryFormatter.Deserialize()`

### Auth or Business Logic

Ask:

- Did attacker input decide who can access or modify a protected object?

Look for:

- client-controlled role or identity
- missing ownership check
- fail-open auth logic
- poisoned session state

### Crypto or Secrets

Ask:

- Is the code using a known-unsafe algorithm or exposing a secret unsafely?

Look for:

- MD5
- DES
- non-crypto RNG for security tokens
- hardcoded credentials
- trust-all TLS logic

## Red Flags That Usually Mean "Not Yet Proven"

- The source is not clearly attacker-controlled.
- The sink is not actually dangerous by itself.
- A framework control may already block the issue.
- The impact depends on assumptions not shown in the code.
- The issue is really a policy disagreement, not a security defect.
- The SCA sample includes a vulnerable package but does not call the affected API.

## Senior Escalation Cases

Escalate if any are true:

- business-logic cases such as IDOR or role abuse depend on app context you cannot prove
- authorization may be enforced in middleware you have not reviewed
- exploitability depends on deployment assumptions not visible in the repo
- the advisory language is ambiguous about the affected API or condition

## Short Review Summary

Use this at the end of the review.

```text
Finding ID:
Verdict:
Confidence: High / Medium / Low
Source:
Sink:
Missing control:
Impact:
One-paragraph justification:
```
