# Intentional Vulnerabilities

106 total findings: 72 SAST true positives, 30 true negatives, 4 SCA.

See [docs/tooling-validation.md](docs/tooling-validation.md) for notes on which findings
are strong cross-tool signals and which are business-logic dependent.

## SAST Vulnerabilities (True Positives)

### Java Module (36 TP)

| ID | CWE | Category | File | Tier | Severity | Description |
|----|-----|----------|------|------|----------|-------------|
| SAST-JAVA-001 | 89 | SQL Injection | `vuln/easy/SqlInjectionDirect.java` | Easy | HIGH | Direct string concat in `Statement.executeQuery()` |
| SAST-JAVA-002 | 79 | XSS (Reflected) | `vuln/easy/XssDirect.java` | Easy | HIGH | User input reflected via `response.getWriter()` |
| SAST-JAVA-003 | 79 | XSS (Stored) | `vuln/easy/XssStoredDirect.java` | Easy | HIGH | DB-stored input rendered without encoding |
| SAST-JAVA-004 | 22 | Path Traversal | `vuln/medium/PathTraversalService.java` | Medium | HIGH | Cross-method file path from user input |
| SAST-JAVA-005 | 918 | SSRF | `vuln/medium/SsrfService.java` | Medium | HIGH | Cross-method URL fetch from user input |
| SAST-JAVA-006 | 502 | Deserialization | `vuln/hard/DeserializationHandler.java` | Hard | CRITICAL | `ObjectInputStream.readObject()` without type filter |
| SAST-JAVA-007 | 639 | IDOR (Horizontal) | `vuln/hard/IdorController.java` | Hard | HIGH | Password-bearing profile returned for another user despite a real session user |
| SAST-JAVA-008 | 639 | IDOR (Vertical) | `vuln/hard/IdorController.java` | Hard | HIGH | Destructive delete authorized by client-supplied role |
| SAST-JAVA-009 | 306 | Auth Bypass | `vuln/ailegacy/AuthBypass.java` | AI | HIGH | Admin-only delete trusts query param instead of server-side auth state |
| SAST-JAVA-010 | 330 | Insecure Random | `vuln/ailegacy/InsecureRandom.java` | AI | MEDIUM | `Math.random()` for session tokens |
| SAST-JAVA-011 | 328 | Weak Hashing | `vuln/ailegacy/WeakHashing.java` | AI | MEDIUM | MD5 for password storage |
| SAST-JAVA-012 | 798 | Hardcoded Secret | `vuln/ailegacy/HardcodedSecrets.java` | AI | HIGH | Hardcoded JWT secret |
| SAST-JAVA-013 | 798 | Hardcoded Secret | `vuln/ailegacy/HardcodedSecrets.java` | AI | HIGH | Hardcoded API key |
| SAST-JAVA-014 | 89 | SQL Injection | `vuln/ailegacy/AiGeneratedDao.java` | AI | HIGH | String-concat SQL in AI-style DAO |
| SAST-JAVA-015 | 78 | Command Injection | `vuln/easy/CommandInjectionDirect.java` | Easy | HIGH | User input concat into `Runtime.exec()` |
| SAST-JAVA-016 | 611 | XXE | `vuln/easy/XxeDirect.java` | Easy | HIGH | Default `DocumentBuilderFactory` allows external entities |
| SAST-JAVA-017 | 601 | Open Redirect | `vuln/easy/OpenRedirectDirect.java` | Easy | HIGH | Unvalidated URL in `sendRedirect()` |
| SAST-JAVA-018 | 117 | Log Injection | `vuln/easy/LogInjectionDirect.java` | Easy | MEDIUM | Unsanitized user input in `Logger.info()` |
| SAST-JAVA-019 | 209 | Error Info Leak | `vuln/easy/ErrorInfoLeakDirect.java` | Easy | MEDIUM | Stack trace written to response |
| SAST-JAVA-020 | 312 | Cleartext Storage | `vuln/easy/CleartextStorageDirect.java` | Easy | HIGH | Credit card stored as plaintext in DB |
| SAST-JAVA-021 | 327 | Weak Cipher | `vuln/easy/WeakCipherDirect.java` | Easy | MEDIUM | DES/ECB with hardcoded key |
| SAST-JAVA-022 | 614 | Insecure Cookie | `vuln/easy/InsecureCookieDirect.java` | Easy | MEDIUM | Cookie without Secure/HttpOnly flags |
| SAST-JAVA-023 | 78 | Command Injection | `vuln/medium/CommandInjectionService.java` | Medium | HIGH | Cross-method via `ProcessBuilder.start()` |
| SAST-JAVA-024 | 89 | SQL Injection | `vuln/medium/SqlInjectionMultiStep.java` | Medium | HIGH | Multi-param cross-method SQL injection |
| SAST-JAVA-025 | 79 | XSS (Header) | `vuln/medium/XssViaHeader.java` | Medium | HIGH | Referer header reflected in HTML response |
| SAST-JAVA-026 | 90 | LDAP Injection | `vuln/medium/LdapInjection.java` | Medium | HIGH | User input concat into LDAP filter |
| SAST-JAVA-027 | 643 | XPath Injection | `vuln/medium/XPathInjection.java` | Medium | HIGH | User input concat into XPath expression |
| SAST-JAVA-028 | 1333 | ReDoS | `vuln/medium/RegexDos.java` | Medium | MEDIUM | User-supplied regex in `Pattern.compile()` |
| SAST-JAVA-029 | 89 | SQL Injection | `vuln/hard/QueryExecutor.java` | Hard | HIGH | 3-file taint chain: SQLi sink in `executeQuery()` |
| SAST-JAVA-030 | 78 | Command Injection | `vuln/hard/CommandRunner.java` | Hard | HIGH | 3-file taint chain: cmdi sink in `Runtime.exec()` |
| SAST-JAVA-031 | 611 | XXE | `vuln/hard/XmlProcessor.java` | Hard | HIGH | Cross-file XXE sink in `DocumentBuilder.parse()` |
| SAST-JAVA-032 | 754 | Exceptional Condition Bypass | `vuln/ailegacy/NullCheckBypass.java` | AI | HIGH | Null token handling fails open and permits admin delete |
| SAST-JAVA-033 | 501 | Trust Boundary | `vuln/ailegacy/TrustBoundaryViolation.java` | AI | HIGH | Session-poisoned role is immediately used to authorize delete |
| SAST-JAVA-034 | 129 | Array Index | `vuln/ailegacy/UnvalidatedArrayIndex.java` | AI | HIGH | User-controlled index selects and executes admin action |
| SAST-JAVA-035 | 295 | Insecure TLS | `vuln/ailegacy/InsecureTlsConfig.java` | AI | HIGH | Trust-all `TrustManager` accepts any certificate |
| SAST-JAVA-036 | 598 | Token in URL | `vuln/ailegacy/CookieInUrl.java` | AI | HIGH | Session token in redirect URL query string |

### .NET Module (36 TP)

| ID | CWE | Category | File | Tier | Severity | Description |
|----|-----|----------|------|------|----------|-------------|
| SAST-DOTNET-001 | 89 | SQL Injection | `Vuln/Easy/SqlInjectionDirect.cs` | Easy | HIGH | String concat in `SqlCommand.ExecuteReader()` |
| SAST-DOTNET-002 | 79 | XSS (Reflected) | `Vuln/Easy/XssDirect.cs` | Easy | HIGH | User input in `Results.Content()` as HTML |
| SAST-DOTNET-003 | 79 | XSS (Stored) | `Vuln/Easy/XssStoredDirect.cs` | Easy | HIGH | DB-stored input rendered without encoding |
| SAST-DOTNET-004 | 22 | Path Traversal | `Vuln/Medium/PathTraversalService.cs` | Medium | HIGH | `Path.Combine()` with user input |
| SAST-DOTNET-005 | 918 | SSRF | `Vuln/Medium/SsrfService.cs` | Medium | HIGH | `HttpClient.GetStringAsync()` with user URL |
| SAST-DOTNET-006 | 502 | Deserialization | `Vuln/Hard/DeserializationHandler.cs` | Hard | CRITICAL | `BinaryFormatter.Deserialize()` without type binder |
| SAST-DOTNET-007 | 639 | IDOR (Horizontal) | `Vuln/Hard/IdorController.cs` | Hard | HIGH | Password-bearing profile returned for another user despite a real session user |
| SAST-DOTNET-008 | 639 | IDOR (Vertical) | `Vuln/Hard/IdorController.cs` | Hard | HIGH | Destructive delete authorized by client-supplied role |
| SAST-DOTNET-009 | 306 | Auth Bypass | `Vuln/AiLegacy/AuthBypass.cs` | AI | HIGH | Admin-only delete trusts query param instead of server-side auth state |
| SAST-DOTNET-010 | 330 | Insecure Random | `Vuln/AiLegacy/InsecureRandom.cs` | AI | MEDIUM | `new Random().Next()` for tokens |
| SAST-DOTNET-011 | 328 | Weak Hashing | `Vuln/AiLegacy/WeakHashing.cs` | AI | MEDIUM | MD5 for password storage |
| SAST-DOTNET-012 | 798 | Hardcoded Secret | `Vuln/AiLegacy/HardcodedSecrets.cs` | AI | HIGH | Hardcoded JWT secret |
| SAST-DOTNET-013 | 798 | Hardcoded Secret | `Vuln/AiLegacy/HardcodedSecrets.cs` | AI | HIGH | Hardcoded API key |
| SAST-DOTNET-014 | 89 | SQL Injection | `Vuln/AiLegacy/AiGeneratedDao.cs` | AI | HIGH | Interpolated SQL in AI-style DAO |
| SAST-DOTNET-015 | 78 | Command Injection | `Vuln/Easy/CommandInjectionDirect.cs` | Easy | HIGH | User input concat into `Process.Start()` |
| SAST-DOTNET-016 | 611 | XXE | `Vuln/Easy/XxeDirect.cs` | Easy | HIGH | DTD processing enabled with `XmlUrlResolver` |
| SAST-DOTNET-017 | 601 | Open Redirect | `Vuln/Easy/OpenRedirectDirect.cs` | Easy | HIGH | Unvalidated URL in `Results.Redirect()` |
| SAST-DOTNET-018 | 117 | Log Injection | `Vuln/Easy/LogInjectionDirect.cs` | Easy | MEDIUM | Unsanitized user input in `Console.WriteLine()` |
| SAST-DOTNET-019 | 209 | Error Info Leak | `Vuln/Easy/ErrorInfoLeakDirect.cs` | Easy | MEDIUM | `ex.ToString()` returned to client |
| SAST-DOTNET-020 | 312 | Cleartext Storage | `Vuln/Easy/CleartextStorageDirect.cs` | Easy | HIGH | Credit card stored as plaintext in DB |
| SAST-DOTNET-021 | 327 | Weak Cipher | `Vuln/Easy/WeakCipherDirect.cs` | Easy | MEDIUM | DES with hardcoded key via `DES.Create()` |
| SAST-DOTNET-022 | 614 | Insecure Cookie | `Vuln/Easy/InsecureCookieDirect.cs` | Easy | MEDIUM | Cookie without Secure/HttpOnly flags |
| SAST-DOTNET-023 | 78 | Command Injection | `Vuln/Medium/CommandInjectionService.cs` | Medium | HIGH | Cross-method via `Process.Start()` |
| SAST-DOTNET-024 | 89 | SQL Injection | `Vuln/Medium/SqlInjectionMultiStep.cs` | Medium | HIGH | Multi-param cross-method SQL injection |
| SAST-DOTNET-025 | 79 | XSS (Header) | `Vuln/Medium/XssViaHeader.cs` | Medium | HIGH | Referer header reflected in HTML response |
| SAST-DOTNET-026 | 90 | LDAP Injection | `Vuln/Medium/LdapInjection.cs` | Medium | HIGH | User input concat into LDAP filter |
| SAST-DOTNET-027 | 643 | XPath Injection | `Vuln/Medium/XPathInjection.cs` | Medium | HIGH | User input concat into XPath expression |
| SAST-DOTNET-028 | 1333 | ReDoS | `Vuln/Medium/RegexDos.cs` | Medium | MEDIUM | User-supplied regex in `new Regex()` |
| SAST-DOTNET-029 | 89 | SQL Injection | `Vuln/Hard/QueryExecutor.cs` | Hard | HIGH | 3-class taint chain: SQLi sink in `ExecuteReader()` |
| SAST-DOTNET-030 | 78 | Command Injection | `Vuln/Hard/CommandRunner.cs` | Hard | HIGH | 3-class taint chain: cmdi sink in `Process.Start()` |
| SAST-DOTNET-031 | 611 | XXE | `Vuln/Hard/XmlProcessor.cs` | Hard | HIGH | Cross-file XXE sink with insecure `XmlReader` settings |
| SAST-DOTNET-032 | 754 | Exceptional Condition Bypass | `Vuln/AiLegacy/NullCheckBypass.cs` | AI | HIGH | Null token handling fails open and permits admin delete |
| SAST-DOTNET-033 | 501 | Trust Boundary | `Vuln/AiLegacy/TrustBoundaryViolation.cs` | AI | HIGH | Session-poisoned role is immediately used to authorize delete |
| SAST-DOTNET-034 | 129 | Array Index | `Vuln/AiLegacy/UnvalidatedArrayIndex.cs` | AI | HIGH | User-controlled index selects and executes admin action |
| SAST-DOTNET-035 | 295 | Insecure TLS | `Vuln/AiLegacy/InsecureTlsConfig.cs` | AI | HIGH | Trust-all `ServerCertificateCustomValidationCallback` |
| SAST-DOTNET-036 | 598 | Token in URL | `Vuln/AiLegacy/CookieInUrl.cs` | AI | HIGH | Session token in redirect URL query string |

## False-Positive Seeds (True Negatives)

### Java Module (10 TN)

| ID | CWE | File | Reason Safe |
|----|-----|------|-------------|
| SAST-JAVA-TN-001 | 79 | `safe/SafeHtmlOutput.java` | Output sanitized via OWASP HTML Sanitizer |
| SAST-JAVA-TN-002 | 89 | `safe/SafeSqlQuery.java` | Parameterized PreparedStatement |
| SAST-JAVA-TN-003 | 89 | `safe/InternalDataQuery.java` | SQL built from internal config, no user input |
| SAST-JAVA-TN-004 | 89 | `safe/DeadCodeVuln.java` | Vulnerable code in private unreachable method |
| SAST-JAVA-TN-005 | 79 | `safe/FrameworkEscaped.java` | OWASP Sanitizers.FORMATTING applied |
| SAST-JAVA-TN-006 | 78 | `safe/SafeCommandExec.java` | Hardcoded command, no user input |
| SAST-JAVA-TN-007 | 601 | `safe/SafeRedirect.java` | Whitelist-validated redirect |
| SAST-JAVA-TN-008 | 611 | `safe/SafeXmlParsing.java` | External entities disabled |
| SAST-JAVA-TN-009 | 117 | `safe/SafeLogging.java` | Input sanitized (newlines stripped) before logging |
| SAST-JAVA-TN-010 | 327 | `safe/SafeCrypto.java` | AES/GCM with proper key generation |
| SAST-JAVA-TN-011 | 22 | `safe/SafePathTraversal.java` | Canonical path enforced under fixed base dir before file read |
| SAST-JAVA-TN-012 | 918 | `safe/SafeSsrfAllowlist.java` | HTTPS + host allowlist before outbound request |
| SAST-JAVA-TN-013 | 639 | `safe/SafeIdorOwnershipCheck.java` | Session ownership or admin role checked before profile access |
| SAST-JAVA-TN-014 | 306 | `safe/SafeAuthzFromSession.java` | Trusted session role checked before delete |
| SAST-JAVA-TN-015 | 1333 | `safe/SafeRegexAllowlist.java` | Regex selected from fixed allowlist |

### .NET Module (10 TN)

| ID | CWE | File | Reason Safe |
|----|-----|------|-------------|
| SAST-DOTNET-TN-001 | 79 | `Safe/SafeHtmlOutput.cs` | Output sanitized via HtmlSanitizer |
| SAST-DOTNET-TN-002 | 89 | `Safe/SafeSqlQuery.cs` | Parameterized SqlCommand |
| SAST-DOTNET-TN-003 | 89 | `Safe/InternalDataQuery.cs` | SQL built from internal config, no user input |
| SAST-DOTNET-TN-004 | 89 | `Safe/DeadCodeVuln.cs` | Vulnerable code in private unreachable method |
| SAST-DOTNET-TN-005 | 79 | `Safe/FrameworkEscaped.cs` | HtmlSanitizer applied before render |
| SAST-DOTNET-TN-006 | 78 | `Safe/SafeCommandExec.cs` | Hardcoded command, no user input |
| SAST-DOTNET-TN-007 | 601 | `Safe/SafeRedirect.cs` | Whitelist-validated redirect |
| SAST-DOTNET-TN-008 | 611 | `Safe/SafeXmlParsing.cs` | DTD processing prohibited |
| SAST-DOTNET-TN-009 | 117 | `Safe/SafeLogging.cs` | Input sanitized (newlines stripped) before logging |
| SAST-DOTNET-TN-010 | 327 | `Safe/SafeCrypto.cs` | AES with randomly generated key and IV |
| SAST-DOTNET-TN-011 | 22 | `Safe/SafePathTraversal.cs` | Canonical path enforced under fixed base dir before file read |
| SAST-DOTNET-TN-012 | 918 | `Safe/SafeSsrfAllowlist.cs` | HTTPS + host allowlist before outbound request |
| SAST-DOTNET-TN-013 | 639 | `Safe/SafeIdorOwnershipCheck.cs` | Session ownership or admin role checked before profile access |
| SAST-DOTNET-TN-014 | 306 | `Safe/SafeAuthzFromSession.cs` | Trusted session role checked before delete |
| SAST-DOTNET-TN-015 | 1333 | `Safe/SafeRegexAllowlist.cs` | Regex selected from fixed allowlist |

## SCA Vulnerabilities

| ID | Language | Package | CVE/GHSA | Reachable | Description |
|----|----------|---------|----------|-----------|-------------|
| SCA-JAVA-001 | Java | logback-core:1.5.6 | CVE-2024-12798 | Yes, with caveat | App calls `JoranConfigurator.doConfigure(...)`; exploitability still depends on attacker-controlled config content/path |
| SCA-JAVA-002 | Java | lz4-java:1.8.0 | CVE-2025-12183 | No | Vulnerable package present, but no lz4 methods are called |
| SCA-DOTNET-001 | .NET | Microsoft.Build:17.14.8 | CVE-2025-55247 | No, as currently implemented | Current sample constructs `new Project(path)`, but does not exercise the advisory's documented `DownloadFile`/Linux temp-dir condition |
| SCA-DOTNET-002 | .NET | NuGet.Packaging:6.8.0 | CVE-2024-0057 / GHSA-68w7-72jg-6qpp | No | Current code only imports the namespace; no NuGet.Packaging APIs are invoked |

## Summary by CWE

| CWE | Name | Count (TP) | Count (TN) |
|-----|------|------------|------------|
| 22 | Path Traversal | 2 | 2 |
| 78 | OS Command Injection | 6 | 2 |
| 79 | Cross-Site Scripting | 8 | 4 |
| 89 | SQL Injection | 10 | 6 |
| 90 | LDAP Injection | 2 | 0 |
| 117 | Log Injection | 2 | 2 |
| 129 | Unvalidated Array Index | 2 | 0 |
| 209 | Error Information Leak | 2 | 0 |
| 295 | Improper Certificate Validation | 2 | 0 |
| 306 | Missing Authentication | 2 | 2 |
| 312 | Cleartext Storage | 2 | 0 |
| 327 | Broken Crypto | 2 | 2 |
| 328 | Weak Hashing | 2 | 0 |
| 330 | Insecure Randomness | 2 | 0 |
| 501 | Trust Boundary Violation | 2 | 0 |
| 502 | Unsafe Deserialization | 2 | 0 |
| 598 | Sensitive Data in URL | 2 | 0 |
| 601 | Open Redirect | 2 | 2 |
| 611 | XXE | 4 | 2 |
| 614 | Insecure Cookie | 2 | 0 |
| 639 | IDOR | 4 | 2 |
| 643 | XPath Injection | 2 | 0 |
| 754 | Improper Check for Exceptional Conditions | 2 | 0 |
| 798 | Hardcoded Credentials | 4 | 0 |
| 918 | SSRF | 2 | 2 |
| 1333 | ReDoS | 2 | 2 |

## Summary by Tier

| Tier | TP | TN | Total |
|------|----|----|-------|
| Easy | 22 | 14 | 36 |
| Medium | 16 | 12 | 28 |
| Hard | 12 | 4 | 16 |
| AI | 22 | 0 | 22 |
| SCA | 4 | 0 | 4 |
| **Total** | **72 SAST TP + 4 SCA** | **30** | **106** |
