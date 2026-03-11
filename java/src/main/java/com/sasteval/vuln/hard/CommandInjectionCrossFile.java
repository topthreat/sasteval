package com.sasteval.vuln.hard;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * CWE-78: OS Command Injection (Cross-File Taint Chain)
 * VULNERABILITY: User input flows through CommandBuilder and CommandRunner across 3 files.
 */
public class CommandInjectionCrossFile extends HttpServlet {

    private final CommandBuilder commandBuilder = new CommandBuilder();
    private final CommandRunner commandRunner = new CommandRunner();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String target = request.getParameter("target");
        response.setContentType("text/plain");

        // VULN: Tainted input flows through CommandBuilder -> CommandRunner
        String cmd = commandBuilder.buildPingCommand(target);
        Process process = commandRunner.runCommand(cmd);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
        }
    }
}
