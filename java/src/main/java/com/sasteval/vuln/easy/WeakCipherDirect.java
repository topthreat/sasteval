package com.sasteval.vuln.easy;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;

/**
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm (Direct)
 * VULNERABILITY: Uses DES with ECB mode and a hardcoded key.
 */
public class WeakCipherDirect extends HttpServlet {

    private static final byte[] HARDCODED_KEY = "12345678".getBytes();

    private String encrypt(String data) throws Exception {
        // VULN: DES is a weak cipher, ECB mode is insecure, and key is hardcoded
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(HARDCODED_KEY, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userData = request.getParameter("data");
        response.setContentType("application/json");

        try {
            String encrypted = encrypt(userData);
            response.getWriter().println("{\"encrypted\": \"" + encrypted + "\"}");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"Encryption failed\"}");
        }
    }
}
