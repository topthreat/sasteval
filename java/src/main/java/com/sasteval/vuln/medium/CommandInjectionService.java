package com.sasteval.vuln.medium;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * CWE-78: OS Command Injection (Cross-Method)
 * VULNERABILITY: User input flows through a helper method into a shell command.
 */
public class CommandInjectionService extends HttpServlet {

    private Process runCommand(String userInput) throws IOException {
        // VULN: User input concatenated into shell command via helper method
        return new ProcessBuilder("/bin/sh", "-c", "ls " + userInput).start();
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String dir = request.getParameter("dir");
        response.setContentType("text/plain");

        Process process = runCommand(dir);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
        }
    }
}
