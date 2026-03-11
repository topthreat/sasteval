package com.sasteval.vuln.ailegacy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * CWE-328: Use of Weak Hash (MD5)
 * VULNERABILITY: Passwords are hashed with MD5 which is cryptographically broken.
 */
public class WeakHashing extends HttpServlet {

    public String hashPassword(String password) throws NoSuchAlgorithmException {
        // VULN: MD5 is broken for password hashing
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());

        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String password = request.getParameter("password");
        response.setContentType("application/json");

        try {
            String hashed = hashPassword(password);
            // "Store" the hashed password (simulated)
            response.getWriter().println("{\"hash\": \"" + hashed + "\", \"status\": \"stored\"}");
        } catch (NoSuchAlgorithmException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"Hashing failed\"}");
        }
    }
}
