#!/bin/bash
# Build the .NET module with debug symbols (.dll + .pdb) for binary-level scanners.
# Produces a Veracode-friendly framework-dependent publish in dotnet/publish/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]; then
    # Prefer the user-space toolchain when it has been installed locally.
    # This keeps the benchmark self-contained in WSL/dev environments.
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$SCRIPT_DIR/../dotnet"

echo "=== Building .NET module (SastEval) ==="
rm -rf ./publish
dotnet publish SastEval.csproj -c Debug -o ./publish -p:UseAppHost=false

if [ -d "./publish" ] && ls ./publish/*.dll 1>/dev/null 2>&1; then
    echo "Build successful: dotnet/publish/"
    echo "DLL count: $(ls ./publish/*.dll | wc -l)"
    echo "PDB count: $(ls ./publish/*.pdb 2>/dev/null | wc -l)"
else
    echo "ERROR: No DLL files found in publish/"
    exit 1
fi
