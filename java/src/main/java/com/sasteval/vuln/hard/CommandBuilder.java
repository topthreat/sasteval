package com.sasteval.vuln.hard;

/**
 * CWE-78: OS Command Injection (Cross-File Helper - Command Builder)
 * Part of a 3-file taint chain: CommandInjectionCrossFile -> CommandBuilder -> CommandRunner.
 */
public class CommandBuilder {

    public String buildPingCommand(String target) {
        // VULN: User input concatenated into shell command string
        return "ping -c 1 " + target;
    }
}
