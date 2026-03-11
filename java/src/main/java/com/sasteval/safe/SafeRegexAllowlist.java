package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * TRUE NEGATIVE for CWE-1333: ReDoS
 * SAFE: User chooses from an allowlist of pre-approved regexes.
 */
public class SafeRegexAllowlist extends HttpServlet {

    private static final Map<String, Pattern> ALLOWED_PATTERNS = new HashMap<>();

    static {
        ALLOWED_PATTERNS.put("digits", Pattern.compile("^\\d+$"));
        ALLOWED_PATTERNS.put("alnum", Pattern.compile("^[A-Za-z0-9]+$"));
        ALLOWED_PATTERNS.put("email", Pattern.compile("^[^@]+@[^@]+\\.[^@]+$"));
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String profile = request.getParameter("profile");
        String input = request.getParameter("input");

        Pattern pattern = ALLOWED_PATTERNS.get(profile);
        if (pattern == null) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Unknown pattern profile\"}");
            return;
        }

        // SAFE: The regex itself is chosen from a fixed allowlist.
        boolean matches = pattern.matcher(input == null ? "" : input).matches();
        response.setContentType("application/json");
        response.getWriter().println("{\"profile\": \"" + profile + "\", \"matches\": " + matches + "}");
    }
}
