package com.sasteval.vuln.medium;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * CWE-79: Cross-Site Scripting via HTTP Header (Cross-Method)
 * VULNERABILITY: HTTP Referer header is reflected in response without encoding.
 */
public class XssViaHeader extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // VULN: Reading from header instead of parameter - still untrusted input
        String referer = request.getHeader("Referer");

        response.setContentType("text/html");
        response.getWriter().println("<html><body>");
        response.getWriter().println("<p>You came from: " + referer + "</p>");
        response.getWriter().println("</body></html>");
    }
}
