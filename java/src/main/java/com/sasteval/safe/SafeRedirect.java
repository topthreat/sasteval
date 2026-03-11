package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * TRUE NEGATIVE for CWE-601: Open Redirect
 * SAFE: Redirects only to whitelisted pages.
 */
public class SafeRedirect extends HttpServlet {

    private static final Set<String> ALLOWED_PAGES = new HashSet<>();

    static {
        ALLOWED_PAGES.add("/home");
        ALLOWED_PAGES.add("/dashboard");
        ALLOWED_PAGES.add("/profile");
        ALLOWED_PAGES.add("/settings");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String page = request.getParameter("page");

        // SAFE: Only redirect if page is in the whitelist
        if (ALLOWED_PAGES.contains(page)) {
            response.sendRedirect(page);
        } else {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.setContentType("application/json");
            response.getWriter().println("{\"error\": \"Invalid redirect target\"}");
        }
    }
}
