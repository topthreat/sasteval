package com.sasteval.vuln.ailegacy;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * CWE-330: Use of Insufficiently Random Values
 * VULNERABILITY: Session token generated using Math.random() which is predictable.
 */
public class InsecureRandom extends HttpServlet {

    public String generateToken() {
        // VULN: Math.random() is not cryptographically secure
        return String.valueOf(Math.random());
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String token = generateToken();

        Cookie cookie = new Cookie("session_token", token);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.setContentType("application/json");
        response.getWriter().println("{\"token\": \"" + token + "\"}");
    }
}
