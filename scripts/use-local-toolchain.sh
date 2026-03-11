#!/bin/bash
# Prefer user-space language toolchains when they are available on the current machine.

LOCAL_JDK="$HOME/.local/opt/jdk-17"
LOCAL_MAVEN="$HOME/.local/opt/apache-maven-3.9.11"
LOCAL_DOTNET="$HOME/.dotnet"

if [ -d "$LOCAL_JDK" ]; then
    export JAVA_HOME="$LOCAL_JDK"
    export PATH="$JAVA_HOME/bin:$PATH"
fi

if [ -d "$LOCAL_MAVEN" ]; then
    export MAVEN_HOME="$LOCAL_MAVEN"
    export PATH="$MAVEN_HOME/bin:$PATH"
fi

if [ -d "$LOCAL_DOTNET" ]; then
    export DOTNET_ROOT="$LOCAL_DOTNET"
    export PATH="$DOTNET_ROOT:$PATH"
fi
