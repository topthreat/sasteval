#!/bin/bash
# Create ready-to-upload Veracode artifacts so users do not need to build locally.
# Produces:
#   veracode/sasteval-java-1.0.0.war
#   veracode/sasteval-dotnet-net8-debug.zip
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERACODE_DIR="$REPO_ROOT/veracode"

"$SCRIPT_DIR/build-java.sh"
"$SCRIPT_DIR/build-dotnet.sh"

mkdir -p "$VERACODE_DIR"
cp "$REPO_ROOT/java/target/sasteval-java-1.0.0.war" "$VERACODE_DIR/"
rm -f "$VERACODE_DIR/sasteval-dotnet-net8-debug.zip"

# Zip the published .NET output with files and folders at the archive root.
(
    cd "$REPO_ROOT/dotnet/publish"
    zip -qr "$VERACODE_DIR/sasteval-dotnet-net8-debug.zip" .
)

echo "Veracode artifacts created:"
ls -lh "$VERACODE_DIR"/sasteval-java-1.0.0.war "$VERACODE_DIR"/sasteval-dotnet-net8-debug.zip
