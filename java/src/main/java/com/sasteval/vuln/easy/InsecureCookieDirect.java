package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;

/**
 * CWE-614: Sensitive Cookie Without 'Secure' Flag
 * VULNERABILITY: Session cookie is created without Secure or HttpOnly flags.
 */
public class InsecureCookieDirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String token = UUID.randomUUID().toString();

        // VULN: Cookie missing Secure and HttpOnly flags
        Cookie sessionCookie = new Cookie("session", token);
        sessionCookie.setMaxAge(3600);
        sessionCookie.setPath("/");
        response.addCookie(sessionCookie);

        response.setContentType("application/json");
        response.getWriter().println("{\"status\": \"session created\"}");
    }
}
