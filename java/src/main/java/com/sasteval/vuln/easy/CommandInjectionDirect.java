package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * CWE-78: OS Command Injection (Direct)
 * VULNERABILITY: User input is concatenated directly into a system command.
 */
public class CommandInjectionDirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String host = request.getParameter("host");
        response.setContentType("text/plain");

        // VULN: Direct concatenation of user input into OS command
        Process process = Runtime.getRuntime().exec("ping " + host);

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.getWriter().println(line);
            }
        }
    }
}
