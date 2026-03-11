#!/bin/bash
# Build the Java module into a .war with debug symbols for binary-level scanners.
# Produces: java/target/sasteval-java-1.0.0.war
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/use-local-toolchain.sh" ]; then
    # Prefer the user-space toolchain when it has been installed locally.
    # This keeps the benchmark self-contained in WSL/dev environments.
    # shellcheck source=/dev/null
    source "$SCRIPT_DIR/use-local-toolchain.sh"
fi

cd "$SCRIPT_DIR/../java"

echo "=== Building Java module (sasteval-java) ==="
mvn clean package -DskipTests -q

WAR_FILE="target/sasteval-java-1.0.0.war"
if [ -f "$WAR_FILE" ]; then
    echo "Build successful: $WAR_FILE"
    echo "Size: $(du -h "$WAR_FILE" | cut -f1)"
else
    echo "ERROR: WAR file not found at $WAR_FILE"
    exit 1
fi
