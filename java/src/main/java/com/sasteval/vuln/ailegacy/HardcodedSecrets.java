package com.sasteval.vuln.ailegacy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * CWE-798: Use of Hard-coded Credentials
 * VULNERABILITY: JWT secret and API key are hardcoded in source code.
 */
public class HardcodedSecrets extends HttpServlet {

    // VULN: Hardcoded secrets in source code
    private static final String JWT_SECRET = "super-secret-jwt-key-12345";
    private static final String API_KEY = "AKIA_EXAMPLE_KEY_DO_NOT_USE";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        response.setContentType("application/json");

        // VULN: Using hardcoded secret to "sign" a token
        String header = Base64.getEncoder().encodeToString(
                "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getEncoder().encodeToString(
                ("{\"sub\":\"" + username + "\",\"admin\":true}").getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getEncoder().encodeToString(
                (header + "." + payload + JWT_SECRET).getBytes(StandardCharsets.UTF_8));

        String token = header + "." + payload + "." + signature;

        response.getWriter().println("{\"token\": \"" + token + "\"}");
    }
}
