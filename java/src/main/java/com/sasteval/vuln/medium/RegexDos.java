package com.sasteval.vuln.medium;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CWE-1333: Inefficient Regular Expression Complexity (ReDoS)
 * VULNERABILITY: User-supplied regex pattern is compiled and matched without validation.
 */
public class RegexDos extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String patternStr = request.getParameter("pattern");
        String input = request.getParameter("input");
        response.setContentType("application/json");

        try {
            // VULN: User-supplied regex pattern compiled without any safeguards
            Pattern pattern = Pattern.compile(patternStr);
            Matcher matcher = pattern.matcher(input);
            boolean matches = matcher.matches();

            response.getWriter().println("{\"matches\": " + matches + "}");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Invalid pattern\"}");
        }
    }
}
