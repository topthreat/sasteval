package com.sasteval.vuln.hard;

import java.io.IOException;

/**
 * CWE-78: OS Command Injection (Cross-File Helper - Command Runner)
 * Part of a 3-file taint chain: CommandInjectionCrossFile -> CommandBuilder -> CommandRunner.
 */
public class CommandRunner {

    public Process runCommand(String cmd) throws IOException {
        // VULN: Executes shell command string without sanitization
        return Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
    }
}
