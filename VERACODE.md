# Veracode Instructions

This repository includes prebuilt artifacts for Veracode Upload and Scan.

Users do not need to install Java, Maven, or .NET to submit this benchmark to Veracode.

Use these files:

- [veracode/sasteval-java-1.0.0.war](veracode/sasteval-java-1.0.0.war)
- [veracode/sasteval-dotnet-net8-debug.zip](veracode/sasteval-dotnet-net8-debug.zip)

## What Veracode Requires

Veracode Upload and Scan requires a packaged artifact that meets the language-specific
packaging guidance.

For this repo:

- Java is packaged as a standard WAR.
- .NET is packaged as a ZIP of `dotnet publish -c Debug -o <OutputFolder> -p:UseAppHost=false`.

These artifacts already match that guidance.

## Recommended Upload Model

Upload the Java and .NET artifacts as separate Veracode application profiles:

- `sasteval-java`
- `sasteval-dotnet`

Reason:

- Veracode treats packaged binaries as modules for analysis, and separate profiles keep
  the benchmark results easier to review and compare against the language-specific ground truth.

## Veracode Platform Steps

Use these steps if you do not want users to install any local Veracode tooling.

### Java

1. In the Veracode Platform, open `My Portfolio > Applications`.
2. Open the `sasteval-java` application profile, or create it if needed.
3. Select `Start a Scan > Start a Static Scan`.
4. Optionally edit the scan name and Auto-Scan setting.
5. Upload [veracode/sasteval-java-1.0.0.war](veracode/sasteval-java-1.0.0.war).
6. After prescan, review the selected modules if Auto-Scan is off.
7. Start the scan, or let Auto-Scan continue automatically.

### .NET

1. In the Veracode Platform, open `My Portfolio > Applications`.
2. Open the `sasteval-dotnet` application profile, or create it if needed.
3. Select `Start a Scan > Start a Static Scan`.
4. Optionally edit the scan name and Auto-Scan setting.
5. Upload [veracode/sasteval-dotnet-net8-debug.zip](veracode/sasteval-dotnet-net8-debug.zip).
6. After prescan, review the selected modules if Auto-Scan is off.
7. Start the scan, or let Auto-Scan continue automatically.

Notes:

- Upload and Scan performs Static Analysis and SCA together if your Veracode account is licensed for both.
- Veracode recommends scanning the same files between scans for the most consistent results.

## API Wrapper Examples

Use these only if you are automating Veracode submission. The Platform flow above is the
no-local-build path for normal users.

### Java wrapper

```bash
java -jar vosp-api-wrapper-java.jar \
  -action uploadandscan \
  -appname sasteval-java \
  -createprofile true \
  -criticality Medium \
  -version "sasteval-java-1.0.0" \
  -filepath /path/to/sasteval/veracode/sasteval-java-1.0.0.war
```

### C# wrapper

```bash
VeracodeC#API.exe \
  -action uploadandscan \
  -appname sasteval-dotnet \
  -createprofile true \
  -criticality Medium \
  -version "sasteval-dotnet-net8-debug" \
  -filepath /path/to/sasteval/veracode/sasteval-dotnet-net8-debug.zip
```

Use your normal Veracode credentials-file or wrapper authentication setup. Veracode
recommends an external API credentials file rather than embedding keys directly in commands.

## Packaging Verification

The included artifacts were prepared to match Veracode's published packaging guidance:

- Java WAR contains:
  - `WEB-INF/`
  - `WEB-INF/classes/`
  - `WEB-INF/lib/`
  - `WEB-INF/web.xml`
- .NET package was produced from:
  - `dotnet publish -c Debug -o <OutputFolder> -p:UseAppHost=false`
- The .NET ZIP contains:
  - `SastEval.dll`
  - `SastEval.pdb`
  - `SastEval.deps.json`
  - `SastEval.runtimeconfig.json`

## Maintainer Regeneration

If you need to regenerate the packaged artifacts:

```bash
./scripts/package-veracode.sh
```

That rebuilds the application and refreshes the files in `veracode/`.

## Sources

- Veracode Upload and Scan: https://docs.veracode.com/r/Veracode_Upload_and_Scan
- Scan code in the Veracode Platform: https://docs.veracode.com/r/Scan_source_code_in_the_Veracode_Platform
- Java packaging: https://docs.veracode.com/r/compilation_java
- .NET packaging: https://docs.veracode.com/r/compilation_net
- `uploadandscan` wrapper action: https://docs.veracode.com/r/r_uploadandscan
