package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * CWE-601: Open Redirect (Direct)
 * VULNERABILITY: User-supplied URL is used in redirect without validation.
 */
public class OpenRedirectDirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String url = request.getParameter("url");

        // VULN: Unvalidated redirect to user-supplied URL
        response.sendRedirect(url);
    }
}
