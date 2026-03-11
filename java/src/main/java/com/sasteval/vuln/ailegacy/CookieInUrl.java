package com.sasteval.vuln.ailegacy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * CWE-598: Use of GET Request Method With Sensitive Query Strings
 * VULNERABILITY: Session token is passed as a URL query parameter.
 */
public class CookieInUrl extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        HttpSession session = request.getSession();
        String token = session.getId();

        // VULN: Sensitive session token exposed in URL query string
        response.sendRedirect("/dashboard?token=" + token);
    }
}
