# Manual Review Report

This report is the handoff version of the benchmark for human reviewers.

Use it when you want to answer two questions:

1. Is this finding a real vulnerability if reviewed manually?
2. How should a junior reviewer prove that from the code?

This report covers all true-positive SAST findings and the 4 SCA findings in the current benchmark. It does not cover the TN controls except where they are useful as contrast.

## Review Standard

Treat a SAST finding as manually confirmed only if all four are true:

1. There is an attacker-controlled source.
2. There is a real dangerous sink or security-relevant decision.
3. There is no effective control between source and sink.
4. The impact is plausible in a normal deployment.

Treat an SCA finding as manually confirmed only if both are true:

1. The dependency version is actually affected by the advisory.
2. The application reaches, or clearly does not reach, the affected code path.

## Reviewer Workflow

For every SAST finding:

1. Open the file and mark the input source.
2. Trace the variable into the sink or authorization decision.
3. Check whether validation, encoding, parameterization, or a framework control blocks the issue.
4. Write down the impact in one sentence.

Use this four-line note format:

```text
Source:
Sink:
Missing control:
Impact:
```

For every SCA finding:

1. Confirm the package name and version in build metadata or dependency inventory.
2. Read the local sample code that imports or calls the package.
3. Compare the code path to the advisory's affected API or condition.
4. Mark the finding as reachable, unreachable, or package-only.

## Finding Families

### SQL Injection

Findings:

- `SAST-JAVA-001` in `java/src/main/java/com/sasteval/vuln/easy/SqlInjectionDirect.java`
- `SAST-DOTNET-001` in `dotnet/Vuln/Easy/SqlInjectionDirect.cs`
- `SAST-JAVA-014` in `java/src/main/java/com/sasteval/vuln/ailegacy/AiGeneratedDao.java`
- `SAST-DOTNET-014` in `dotnet/Vuln/AiLegacy/AiGeneratedDao.cs`
- `SAST-JAVA-024` in `java/src/main/java/com/sasteval/vuln/medium/SqlInjectionMultiStep.java`
- `SAST-DOTNET-024` in `dotnet/Vuln/Medium/SqlInjectionMultiStep.cs`
- `SAST-JAVA-029` in `java/src/main/java/com/sasteval/vuln/hard/QueryExecutor.java`
- `SAST-DOTNET-029` in `dotnet/Vuln/Hard/QueryExecutor.cs`

Why these are legitimate:

- Untrusted request data is concatenated or interpolated into SQL text.
- The final SQL text is executed by `executeQuery()`, `ExecuteReader()`, or `ExecuteNonQuery()`.
- The dangerous part is the query shape being attacker-influenced, not just the data value.

How to manually verify:

1. Find the request parameter or method argument that originates from user input.
2. Confirm it is inserted into SQL text with string concatenation or interpolation.
3. Confirm the SQL text reaches a database execution method.
4. Confirm there is no `PreparedStatement` parameter binding or equivalent safe API for the tainted portion.
5. Write the impact as "attacker can change query logic or data scope."

### Cross-Site Scripting

Findings:

- `SAST-JAVA-002` in `java/src/main/java/com/sasteval/vuln/easy/XssDirect.java`
- `SAST-DOTNET-002` in `dotnet/Vuln/Easy/XssDirect.cs`
- `SAST-JAVA-003` in `java/src/main/java/com/sasteval/vuln/easy/XssStoredDirect.java`
- `SAST-DOTNET-003` in `dotnet/Vuln/Easy/XssStoredDirect.cs`
- `SAST-JAVA-025` in `java/src/main/java/com/sasteval/vuln/medium/XssViaHeader.java`
- `SAST-DOTNET-025` in `dotnet/Vuln/Medium/XssViaHeader.cs`

Why these are legitimate:

- Untrusted data is placed into HTML output.
- The response is emitted as raw HTML, not safely encoded output.
- Stored cases are still XSS because the data was attacker-controlled before being stored.

How to manually verify:

1. Identify the source: request parameter, header, or database value previously sourced from user input.
2. Confirm the value is inserted into HTML markup.
3. Confirm no output encoding or sanitizer runs on the value before rendering.
4. For stored cases, confirm the application reads from storage and writes raw content back to the browser.
5. Write the impact as "attacker can execute script in another user's browser."

### Path Traversal

Findings:

- `SAST-JAVA-004` in `java/src/main/java/com/sasteval/vuln/medium/PathTraversalService.java`
- `SAST-DOTNET-004` in `dotnet/Vuln/Medium/PathTraversalService.cs`

Why these are legitimate:

- User-controlled path segments reach file read APIs.
- The code does not enforce a fixed base directory after canonicalization.

How to manually verify:

1. Find the request-controlled filename or path.
2. Trace it into `FileInputStream` or `File.ReadAllBytes()`.
3. Check whether the code resolves and then validates that the final path stays under an allowlisted root.
4. If no such validation exists, conclude traversal is possible.
5. Write the impact as "attacker can read unintended files."

### SSRF

Findings:

- `SAST-JAVA-005` in `java/src/main/java/com/sasteval/vuln/medium/SsrfService.java`
- `SAST-DOTNET-005` in `dotnet/Vuln/Medium/SsrfService.cs`

Why these are legitimate:

- User input is treated as a URL.
- The application makes a server-side outbound request to that URL without allowlisting.

How to manually verify:

1. Identify the untrusted URL source.
2. Confirm it reaches `openConnection()` or `GetStringAsync()`.
3. Check for missing scheme, host, IP range, or destination allowlist validation.
4. Confirm the server, not the browser, performs the request.
5. Write the impact as "attacker can make the server fetch internal or attacker-chosen resources."

### Unsafe Deserialization

Findings:

- `SAST-JAVA-006` in `java/src/main/java/com/sasteval/vuln/hard/DeserializationHandler.java`
- `SAST-DOTNET-006` in `dotnet/Vuln/Hard/DeserializationHandler.cs`

Why these are legitimate:

- Untrusted serialized bytes are deserialized directly.
- No type allowlist or safe serializer restriction is enforced.

How to manually verify:

1. Confirm the serialized bytes come from request input or another untrusted boundary.
2. Confirm the code calls `readObject()` or `BinaryFormatter.Deserialize()`.
3. Check for absence of type filtering, binder restrictions, or a safe serialization format.
4. Write the impact as "attacker can instantiate unexpected object graphs, potentially leading to code execution or logic abuse."

### IDOR

Findings:

- `SAST-JAVA-007` in `java/src/main/java/com/sasteval/vuln/hard/IdorController.java`
- `SAST-DOTNET-007` in `dotnet/Vuln/Hard/IdorController.cs`
- `SAST-JAVA-008` in `java/src/main/java/com/sasteval/vuln/hard/IdorController.java`
- `SAST-DOTNET-008` in `dotnet/Vuln/Hard/IdorController.cs`

Why these are legitimate:

- The application has a real session user.
- The code uses attacker-controlled object identifiers or roles to authorize access or deletion.
- The missing control is ownership or privilege enforcement, not input validation.

How to manually verify:

1. Confirm the code establishes or reads a server-side session identity.
2. Find the user-controlled `userId` or `role` input.
3. Confirm the code uses that input to fetch another user's data or authorize a destructive action.
4. Confirm there is no server-side ownership check such as "requested object belongs to session user" and no server-side role source.
5. Write the impact as "attacker can access or modify objects they do not own."

Reviewer note:

- These are real vulnerabilities, but they are business-logic findings, so manual review is more reliable than generic SAST.

### Authentication Bypass

Findings:

- `SAST-JAVA-009` in `java/src/main/java/com/sasteval/vuln/ailegacy/AuthBypass.java`
- `SAST-DOTNET-009` in `dotnet/Vuln/AiLegacy/AuthBypass.cs`

Why these are legitimate:

- The code uses a client-supplied flag to decide whether an admin-only action is allowed.
- The application does not rely on server-side identity or role state for the decision.

How to manually verify:

1. Find the request parameter such as `isAdmin`.
2. Confirm the code branches on that value.
3. Confirm the privileged branch reaches a real admin action such as delete.
4. Confirm no trusted server-side auth check guards the same action.
5. Write the impact as "attacker can self-assert admin status."

### Insecure Randomness

Findings:

- `SAST-JAVA-010` in `java/src/main/java/com/sasteval/vuln/ailegacy/InsecureRandom.java`
- `SAST-DOTNET-010` in `dotnet/Vuln/AiLegacy/InsecureRandom.cs`

Why these are legitimate:

- Tokens are generated with non-cryptographic RNGs.
- The generated values are used for a security purpose.

How to manually verify:

1. Confirm the code creates a token, session value, reset value, or other security-sensitive secret.
2. Confirm the source is `Math.random()` or `System.Random`.
3. Confirm no cryptographic RNG replaces or wraps the output.
4. Write the impact as "tokens may be guessable or statistically predictable."

### Weak Hashing

Findings:

- `SAST-JAVA-011` in `java/src/main/java/com/sasteval/vuln/ailegacy/WeakHashing.java`
- `SAST-DOTNET-011` in `dotnet/Vuln/AiLegacy/WeakHashing.cs`

Why these are legitimate:

- MD5 is used for password hashing.
- MD5 is not appropriate for password storage.

How to manually verify:

1. Confirm the code hashes a password or password-equivalent secret.
2. Confirm the algorithm is `MD5`.
3. Confirm there is no password-specific KDF such as bcrypt, scrypt, Argon2, or PBKDF2.
4. Write the impact as "stored password hashes are weak against cracking."

### Hardcoded Secrets

Findings:

- `SAST-JAVA-012` in `java/src/main/java/com/sasteval/vuln/ailegacy/HardcodedSecrets.java`
- `SAST-DOTNET-012` in `dotnet/Vuln/AiLegacy/HardcodedSecrets.cs`
- `SAST-JAVA-013` in `java/src/main/java/com/sasteval/vuln/ailegacy/HardcodedSecrets.java`
- `SAST-DOTNET-013` in `dotnet/Vuln/AiLegacy/HardcodedSecrets.cs`

Why these are legitimate:

- Long-lived secrets are embedded directly in source code as constants.
- The issue exists even if the values are examples because the pattern is operationally unsafe.

How to manually verify:

1. Confirm the value is a credential, signing key, or API secret.
2. Confirm it is stored directly in code, not loaded from environment or secret management.
3. Confirm the application uses it for authentication, signing, or API access.
4. Write the impact as "source disclosure or repository access compromises the secret."

### Command Injection

Findings:

- `SAST-JAVA-015` in `java/src/main/java/com/sasteval/vuln/easy/CommandInjectionDirect.java`
- `SAST-DOTNET-015` in `dotnet/Vuln/Easy/CommandInjectionDirect.cs`
- `SAST-JAVA-023` in `java/src/main/java/com/sasteval/vuln/medium/CommandInjectionService.java`
- `SAST-DOTNET-023` in `dotnet/Vuln/Medium/CommandInjectionService.cs`
- `SAST-JAVA-030` in `java/src/main/java/com/sasteval/vuln/hard/CommandRunner.java`
- `SAST-DOTNET-030` in `dotnet/Vuln/Hard/CommandRunner.cs`

Why these are legitimate:

- User input becomes part of an OS command string.
- The application invokes a shell or command interpreter.

How to manually verify:

1. Trace the user-controlled value into the command string or argument vector.
2. Confirm the sink is `Runtime.exec()`, `ProcessBuilder.start()`, or `Process.Start()`.
3. Check whether the command is shell-evaluated or otherwise attacker-influenced as code, not just passed as a fixed argument to a safe binary.
4. Confirm there is no strict allowlist or argument separation that neutralizes metacharacters.
5. Write the impact as "attacker can execute arbitrary commands or alter command behavior."

### XML External Entity Injection

Findings:

- `SAST-JAVA-016` in `java/src/main/java/com/sasteval/vuln/easy/XxeDirect.java`
- `SAST-DOTNET-016` in `dotnet/Vuln/Easy/XxeDirect.cs`
- `SAST-JAVA-031` in `java/src/main/java/com/sasteval/vuln/hard/XmlProcessor.java`
- `SAST-DOTNET-031` in `dotnet/Vuln/Hard/XmlProcessor.cs`

Why these are legitimate:

- The code parses attacker-controlled XML.
- DTD or external entity resolution is not disabled.

How to manually verify:

1. Confirm the XML comes from request input or another untrusted boundary.
2. Confirm the parser is created with default insecure settings or explicit DTD/entity support.
3. Check for absence of secure features that disable external entities and DTD processing.
4. Write the impact as "attacker can make the parser resolve external entities, potentially reading files or making network requests."

### Open Redirect

Findings:

- `SAST-JAVA-017` in `java/src/main/java/com/sasteval/vuln/easy/OpenRedirectDirect.java`
- `SAST-DOTNET-017` in `dotnet/Vuln/Easy/OpenRedirectDirect.cs`

Why these are legitimate:

- User-controlled URLs are passed directly to redirect APIs.
- There is no same-site restriction or allowlist.

How to manually verify:

1. Identify the request parameter that supplies the redirect target.
2. Confirm it flows into `sendRedirect()` or `Results.Redirect()`.
3. Confirm there is no host, path, or allowlist validation.
4. Write the impact as "attacker can redirect users to attacker-controlled destinations."

### Log Injection

Findings:

- `SAST-JAVA-018` in `java/src/main/java/com/sasteval/vuln/easy/LogInjectionDirect.java`
- `SAST-DOTNET-018` in `dotnet/Vuln/Easy/LogInjectionDirect.cs`

Why these are legitimate:

- Untrusted input is written directly to logs.
- No newline or delimiter neutralization is applied.

How to manually verify:

1. Confirm the source is attacker-controlled input.
2. Confirm it is logged directly.
3. Confirm no sanitization removes line breaks or log control characters.
4. Write the impact as "attacker can forge or corrupt log records."

### Error Information Leakage

Findings:

- `SAST-JAVA-019` in `java/src/main/java/com/sasteval/vuln/easy/ErrorInfoLeakDirect.java`
- `SAST-DOTNET-019` in `dotnet/Vuln/Easy/ErrorInfoLeakDirect.cs`

Why these are legitimate:

- Detailed exception output is returned to the client.
- Stack traces and internal details aid attackers.

How to manually verify:

1. Confirm an exception object is rendered to the HTTP response.
2. Confirm the rendered content includes stack traces, type names, or internal implementation details.
3. Confirm there is no generic error handler replacing it with a safe message.
4. Write the impact as "attacker learns internal paths, class names, or logic details."

### Cleartext Storage of Sensitive Data

Findings:

- `SAST-JAVA-020` in `java/src/main/java/com/sasteval/vuln/easy/CleartextStorageDirect.java`
- `SAST-DOTNET-020` in `dotnet/Vuln/Easy/CleartextStorageDirect.cs`

Why these are legitimate:

- Sensitive payment data is stored directly without encryption or tokenization.

How to manually verify:

1. Confirm the data is sensitive, such as a full credit card number.
2. Confirm the code writes it directly to the database.
3. Confirm no encryption, tokenization, or approved vault abstraction is applied before storage.
4. Write the impact as "database compromise exposes raw payment data."

### Weak Cipher

Findings:

- `SAST-JAVA-021` in `java/src/main/java/com/sasteval/vuln/easy/WeakCipherDirect.java`
- `SAST-DOTNET-021` in `dotnet/Vuln/Easy/WeakCipherDirect.cs`

Why these are legitimate:

- DES is used for confidentiality.
- The Java case also uses ECB mode, which is especially weak.

How to manually verify:

1. Confirm the code is performing real encryption, not compatibility parsing or a test fixture.
2. Confirm the algorithm is DES or another obsolete cipher.
3. In Java, note the insecure mode if present, such as ECB.
4. Write the impact as "encrypted data relies on obsolete cryptography."

### Insecure Cookie Flags

Findings:

- `SAST-JAVA-022` in `java/src/main/java/com/sasteval/vuln/easy/InsecureCookieDirect.java`
- `SAST-DOTNET-022` in `dotnet/Vuln/Easy/InsecureCookieDirect.cs`

Why these are legitimate:

- Session-like cookies are set without `Secure` and `HttpOnly`.

How to manually verify:

1. Confirm the cookie carries session or authentication state.
2. Confirm the code sets the cookie without `Secure` and without `HttpOnly`.
3. Write the impact as "cookie is more exposed to network interception or client-side script access."

### LDAP Injection

Findings:

- `SAST-JAVA-026` in `java/src/main/java/com/sasteval/vuln/medium/LdapInjection.java`
- `SAST-DOTNET-026` in `dotnet/Vuln/Medium/LdapInjection.cs`

Why these are legitimate:

- User input is concatenated into an LDAP filter expression.

How to manually verify:

1. Identify the request-controlled username or filter fragment.
2. Confirm the code concatenates it into the LDAP filter string.
3. Confirm that filter reaches `ctx.search()` or `DirectorySearcher`.
4. Confirm no LDAP escaping is applied.
5. Write the impact as "attacker can alter directory search logic."

### XPath Injection

Findings:

- `SAST-JAVA-027` in `java/src/main/java/com/sasteval/vuln/medium/XPathInjection.java`
- `SAST-DOTNET-027` in `dotnet/Vuln/Medium/XPathInjection.cs`

Why these are legitimate:

- User input is concatenated into an XPath expression.

How to manually verify:

1. Identify the untrusted input.
2. Confirm it is inserted into an XPath string.
3. Confirm the expression is executed by `xpath.evaluate()` or `SelectSingleNode()`.
4. Confirm no strict allowlist or safe parameterization approach is used.
5. Write the impact as "attacker can alter XML query logic."

### Regular Expression Denial of Service

Findings:

- `SAST-JAVA-028` in `java/src/main/java/com/sasteval/vuln/medium/RegexDos.java`
- `SAST-DOTNET-028` in `dotnet/Vuln/Medium/RegexDos.cs`

Why these are legitimate:

- The regex pattern itself is attacker-controlled.
- Compiling and using attacker-controlled patterns can trigger pathological backtracking or CPU exhaustion.

How to manually verify:

1. Confirm the regex pattern string comes from untrusted input.
2. Confirm the application compiles it with `Pattern.compile()` or `new Regex()`.
3. Check for missing pattern restrictions, timeouts, or allowlists.
4. Write the impact as "attacker can supply expensive patterns and consume CPU."

### Exceptional Condition Bypass

Findings:

- `SAST-JAVA-032` in `java/src/main/java/com/sasteval/vuln/ailegacy/NullCheckBypass.java`
- `SAST-DOTNET-032` in `dotnet/Vuln/AiLegacy/NullCheckBypass.cs`

Why these are legitimate:

- Null or malformed input causes the auth logic to fail open.
- The failure path grants access to a privileged delete action.

How to manually verify:

1. Identify the nullable or malformed token input.
2. Trace the normal authorization path.
3. Trace the exception or null path and confirm it sets or implies an authorized outcome.
4. Confirm the privileged sink is still executed.
5. Write the impact as "attacker can trigger an error path to bypass authorization."

Reviewer note:

- This is a real security bug, but it is less pattern-stable than classic injection flaws.

### Trust Boundary Violation

Findings:

- `SAST-JAVA-033` in `java/src/main/java/com/sasteval/vuln/ailegacy/TrustBoundaryViolation.java`
- `SAST-DOTNET-033` in `dotnet/Vuln/AiLegacy/TrustBoundaryViolation.cs`

Why these are legitimate:

- The application copies user-controlled role data into server-side session state.
- That poisoned session role is then trusted for authorization.

How to manually verify:

1. Find the request-controlled role value.
2. Confirm the code writes it into session state.
3. Confirm a later authorization check trusts that session value.
4. Confirm the check protects a destructive operation.
5. Write the impact as "attacker can poison trusted state and gain privileges."

Reviewer note:

- This is another business-logic-heavy issue. Manual confirmation matters more than generic SAST support.

### Unvalidated Array Index Leading to Dangerous Action

Findings:

- `SAST-JAVA-034` in `java/src/main/java/com/sasteval/vuln/ailegacy/UnvalidatedArrayIndex.java`
- `SAST-DOTNET-034` in `dotnet/Vuln/AiLegacy/UnvalidatedArrayIndex.cs`

Why these are legitimate:

- User input selects an internal action by array index.
- The selected action performs an admin operation.

How to manually verify:

1. Confirm the index is attacker-controlled.
2. Confirm there is no bounds or semantic validation of allowed actions.
3. Confirm the array or dispatch table contains dangerous admin actions.
4. Confirm the chosen action is executed.
5. Write the impact as "attacker can select privileged internal behavior."

### Insecure TLS Validation

Findings:

- `SAST-JAVA-035` in `java/src/main/java/com/sasteval/vuln/ailegacy/InsecureTlsConfig.java`
- `SAST-DOTNET-035` in `dotnet/Vuln/AiLegacy/InsecureTlsConfig.cs`

Why these are legitimate:

- The code disables certificate validation by accepting any certificate.

How to manually verify:

1. Confirm a custom trust hook or callback is registered.
2. Confirm it unconditionally trusts certificates or returns `true`.
3. Confirm the client is used for network communication.
4. Write the impact as "attacker can perform MITM against TLS connections."

### Sensitive Token in URL

Findings:

- `SAST-JAVA-036` in `java/src/main/java/com/sasteval/vuln/ailegacy/CookieInUrl.java`
- `SAST-DOTNET-036` in `dotnet/Vuln/AiLegacy/CookieInUrl.cs`

Why these are legitimate:

- Session or bearer-like tokens are placed into redirect URLs.
- URLs leak into browser history, logs, proxies, and referer headers.

How to manually verify:

1. Confirm the value is a session token or bearer-like secret.
2. Confirm it is appended to a redirect URL query string.
3. Confirm the redirect is actually issued.
4. Write the impact as "sensitive token can leak through URL handling and logging."

## SCA Findings

### SCA-JAVA-001

File:

- `java/src/main/java/com/sasteval/sca/LogbackReachable.java`

Manual verdict:

- The dependency vulnerability is real.
- The sample has a plausible reachable path because app code calls `JoranConfigurator.doConfigure(...)`.
- Final exploitability still depends on attacker control of the configuration content or path.

How to manually verify:

1. Confirm `logback-core:1.5.6` is present in the build.
2. Read the advisory and note the affected API or behavior.
3. Confirm application code calls `JoranConfigurator.doConfigure(...)`.
4. Confirm the argument can be influenced by an attacker in the benchmark sample.
5. Mark this as "reachable with caveat."

### SCA-JAVA-002

File:

- `java/src/main/java/com/sasteval/sca/Lz4Unreachable.java`

Manual verdict:

- The package version is vulnerable.
- The benchmark code does not call lz4 functionality, so the advisory is not reachable from app logic.

How to manually verify:

1. Confirm `lz4-java:1.8.0` is present.
2. Search the codebase for lz4 API usage.
3. Confirm the sample only imports or references the package without executing affected methods.
4. Mark this as "package present, unreachable."

### SCA-DOTNET-001

File:

- `dotnet/Sca/MsBuildUnreachable.cs`

Manual verdict:

- The Microsoft.Build advisory is real.
- The current sample does not prove advisory-specific reachability.
- Do not score this as a reachable application vulnerability in its current form.

How to manually verify:

1. Confirm `Microsoft.Build:17.14.8` is present.
2. Read the advisory and identify the documented affected condition.
3. Compare the sample code to that condition.
4. Confirm the benchmark creates `new Project(path)` but does not exercise the documented `DownloadFile` and Linux temp-directory condition.
5. Mark this as "dependency present, reachability not demonstrated."

### SCA-DOTNET-002

File:

- `dotnet/Sca/NuGetPackagingUnreachable.cs`

Manual verdict:

- The package advisory is real.
- The sample does not invoke NuGet.Packaging APIs, so the benchmark does not reach the vulnerable behavior.

How to manually verify:

1. Confirm `NuGet.Packaging:6.8.0` is present.
2. Search the sample for actual NuGet.Packaging API calls.
3. Confirm the sample contains only namespace presence or inert reference usage.
4. Mark this as "package present, unreachable."

## Reviewer Shortcuts

If a junior reviewer is unsure, tell them to ask these by category:

- Injection family: "Did attacker input become executable syntax?"
- Output family: "Did attacker input become raw browser-visible markup?"
- File or network family: "Did attacker input choose what the server read or fetched?"
- Auth family: "Did attacker input decide who is allowed to do something?"
- Crypto family: "Is the code using an algorithm or secret-handling pattern that is already known to be unsafe?"
- SCA family: "Is the vulnerable dependency present, and does the app actually call the affected behavior?"

## Notes on Business-Logic Findings

`IDOR`, `Auth Bypass`, `Exceptional Condition Bypass`, and `Trust Boundary Violation`
are manually defensible but more context-heavy than classic source-to-sink injection
cases. When comparing scanner results, treat these separately from the core taint-flow
findings. See [tooling-validation.md](tooling-validation.md) for details on which
findings are strong cross-tool signals.
