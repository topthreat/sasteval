package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * CWE-117: Log Injection (Direct)
 * VULNERABILITY: User input is written directly to log without sanitization.
 */
public class LogInjectionDirect extends HttpServlet {

    private static final Logger logger = Logger.getLogger(LogInjectionDirect.class.getName());

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");

        // VULN: Unsanitized user input written to log (allows log forging)
        logger.info("Login attempt for: " + username);

        response.setContentType("application/json");
        response.getWriter().println("{\"status\": \"login attempt logged\"}");
    }
}
