package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * TRUE NEGATIVE for CWE-117: Log Injection
 * SAFE: User input is sanitized (newlines and carriage returns removed) before logging.
 */
public class SafeLogging extends HttpServlet {

    private static final Logger logger = Logger.getLogger(SafeLogging.class.getName());

    private String sanitizeForLog(String input) {
        if (input == null) {
            return "null";
        }
        // SAFE: Strip newlines and carriage returns to prevent log injection
        return input.replace("\n", "").replace("\r", "").replace("\t", "");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");

        // SAFE: Sanitized input logged
        String sanitized = sanitizeForLog(username);
        logger.info("Login attempt for: " + sanitized);

        response.setContentType("application/json");
        response.getWriter().println("{\"status\": \"login attempt logged\"}");
    }
}
