package com.sasteval.safe;

import org.owasp.html.Sanitizers;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TRUE NEGATIVE for CWE-79: XSS
 * SAFE: User input is sanitized using OWASP HTML Sanitizer with FORMATTING and BLOCKS policies.
 */
public class FrameworkEscaped extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String input = request.getParameter("input");
        response.setContentType("text/html");

        // SAFE: OWASP sanitizer strips dangerous HTML
        String sanitized = Sanitizers.FORMATTING.and(Sanitizers.BLOCKS).sanitize(input);
        response.getWriter().println("<div>" + sanitized + "</div>");
    }
}
