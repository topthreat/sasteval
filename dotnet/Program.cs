using SastEval.Util;
using SastEval.Vuln.Easy;
using SastEval.Vuln.Medium;
using SastEval.Vuln.Hard;
using SastEval.Vuln.AiLegacy;
using SastEval.Safe;
using SastEval.Sca;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession();
var app = builder.Build();
app.UseSession();

// Initialize database schema
DbUtil.GetConnection();

// --- Easy tier vulnerabilities ---
app.MapGet("/vuln/easy/sqli", SqlInjectionDirect.Handle);
app.MapGet("/vuln/easy/xss", XssDirect.Handle);
app.MapPost("/vuln/easy/xss-stored", XssStoredDirect.HandlePost);
app.MapGet("/vuln/easy/xss-stored", XssStoredDirect.HandleGet);
app.MapGet("/vuln/easy/cmdi", CommandInjectionDirect.Handle);
app.MapPost("/vuln/easy/xxe", (Delegate)XxeDirect.Handle);
app.MapGet("/vuln/easy/open-redirect", OpenRedirectDirect.Handle);
app.MapGet("/vuln/easy/log-injection", LogInjectionDirect.Handle);
app.MapGet("/vuln/easy/error-info-leak", ErrorInfoLeakDirect.Handle);
app.MapGet("/vuln/easy/cleartext-storage", CleartextStorageDirect.Handle);
app.MapGet("/vuln/easy/weak-cipher", WeakCipherDirect.Handle);
app.MapGet("/vuln/easy/insecure-cookie", InsecureCookieDirect.Handle);

// --- Medium tier vulnerabilities ---
app.MapGet("/vuln/medium/path-traversal", PathTraversalService.Handle);
app.MapGet("/vuln/medium/ssrf", (Delegate)SsrfService.Handle);
app.MapGet("/vuln/medium/cmdi", CommandInjectionService.Handle);
app.MapGet("/vuln/medium/sqli-multistep", SqlInjectionMultiStep.Handle);
app.MapGet("/vuln/medium/xss-header", XssViaHeader.Handle);
app.MapGet("/vuln/medium/ldap-injection", LdapInjection.Handle);
app.MapGet("/vuln/medium/xpath-injection", XPathInjection.Handle);
app.MapGet("/vuln/medium/regex-dos", RegexDos.Handle);

// --- Hard tier vulnerabilities ---
app.MapPost("/vuln/hard/deserialization", (Delegate)DeserializationEndpoint.Handle);
app.MapGet("/vuln/hard/idor", IdorController.HandleGet);
app.MapPost("/vuln/hard/idor", IdorController.HandlePost);
app.MapGet("/vuln/hard/sqli-crossfile", SqlInjectionCrossFile.Handle);
app.MapGet("/vuln/hard/cmdi-crossfile", CommandInjectionCrossFile.Handle);
app.MapPost("/vuln/hard/xxe-crossfile", (Delegate)XxeCrossFile.Handle);

// --- AI-Legacy module ---
app.MapGet("/vuln/ailegacy/auth-bypass", AuthBypass.Handle);
app.MapGet("/vuln/ailegacy/insecure-random", InsecureRandom.Handle);
app.MapGet("/vuln/ailegacy/weak-hash", WeakHashing.Handle);
app.MapGet("/vuln/ailegacy/hardcoded-secrets", HardcodedSecrets.Handle);
app.MapGet("/vuln/ailegacy/ai-dao/create", AiGeneratedDao.HandleCreate);
app.MapGet("/vuln/ailegacy/ai-dao/read", AiGeneratedDao.HandleRead);
app.MapGet("/vuln/ailegacy/ai-dao/update", AiGeneratedDao.HandleUpdate);
app.MapGet("/vuln/ailegacy/ai-dao/delete", AiGeneratedDao.HandleDelete);
app.MapGet("/vuln/ailegacy/null-check-bypass", NullCheckBypass.Handle);
app.MapGet("/vuln/ailegacy/trust-boundary", TrustBoundaryViolation.Handle);
app.MapGet("/vuln/ailegacy/array-index", UnvalidatedArrayIndex.Handle);
app.MapGet("/vuln/ailegacy/insecure-tls", (Delegate)InsecureTlsConfig.Handle);
app.MapGet("/vuln/ailegacy/cookie-in-url", CookieInUrl.Handle);

// --- False-positive seeds (safe code) ---
app.MapGet("/safe/html-output", SafeHtmlOutput.Handle);
app.MapGet("/safe/sql-query", SafeSqlQuery.Handle);
app.MapGet("/safe/internal-data", InternalDataQuery.Handle);
app.MapGet("/safe/dead-code", DeadCodeVuln.Handle);
app.MapGet("/safe/framework-escaped", FrameworkEscaped.Handle);
app.MapGet("/safe/command-exec", SafeCommandExec.Handle);
app.MapGet("/safe/redirect", SafeRedirect.Handle);
app.MapPost("/safe/xml-parsing", (Delegate)SafeXmlParsing.Handle);
app.MapGet("/safe/logging", SafeLogging.Handle);
app.MapGet("/safe/crypto", SafeCrypto.Handle);
app.MapGet("/safe/path-traversal", SafePathTraversal.Handle);
app.MapGet("/safe/ssrf", (Delegate)SafeSsrfAllowlist.Handle);
app.MapGet("/safe/idor", SafeIdorOwnershipCheck.Handle);
app.MapPost("/safe/authz", SafeAuthzFromSession.Handle);
app.MapGet("/safe/regex", SafeRegexAllowlist.Handle);

// --- SCA reachability ---
app.MapGet("/sca/msbuild-unreachable", MsBuildUnreachable.Handle);
app.MapGet("/sca/nuget-unreachable", NuGetPackagingUnreachable.Handle);

app.Run();
