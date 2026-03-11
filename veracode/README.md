# Veracode Upload Artifacts

This directory contains the packaged artifacts intended for Veracode Upload and Scan.

Use these files directly:

- `sasteval-java-1.0.0.war`
- `sasteval-dotnet-net8-debug.zip`

What each file is:

- `sasteval-java-1.0.0.war`
  A compiled Java WAR containing application classes in `WEB-INF/classes`, dependencies in
  `WEB-INF/lib`, and a valid `WEB-INF/web.xml`.
- `sasteval-dotnet-net8-debug.zip`
  A ZIP of the framework-dependent `dotnet publish` output created with `-p:UseAppHost=false`.
  The archive root contains the published DLLs, PDBs, `deps.json`, and runtime files Veracode
  expects for .NET static analysis.

Recommended upload model:

- Upload `sasteval-java-1.0.0.war` to one Veracode application profile.
- Upload `sasteval-dotnet-net8-debug.zip` to a separate Veracode application profile.

Reason:

- Veracode will treat Java and .NET as separate top-level modules, and separate profiles keep
  the benchmark results easier to review and score.

Maintainer note:

- To regenerate these files, run `./scripts/package-veracode.sh`.
