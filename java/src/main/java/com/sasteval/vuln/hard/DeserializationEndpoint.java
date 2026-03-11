package com.sasteval.vuln.hard;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * CWE-502: Deserialization of Untrusted Data
 * VULNERABILITY: Reads raw bytes from request and deserializes without validation.
 */
public class DeserializationEndpoint extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        // VULN: Read raw bytes from request body and pass to unsafe deserializer
        byte[] bytes = request.getInputStream().readAllBytes();

        try {
            Object obj = DeserializationHandler.deserialize(bytes);
            response.setContentType("application/json");
            response.getWriter().println("{\"class\": \"" + obj.getClass().getName() + "\"}");
        } catch (ClassNotFoundException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Deserialization failed\"}");
        }
    }
}
