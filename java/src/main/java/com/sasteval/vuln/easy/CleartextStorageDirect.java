package com.sasteval.vuln.easy;

import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * CWE-312: Cleartext Storage of Sensitive Information (Direct)
 * VULNERABILITY: Credit card number is stored in the database without encryption.
 */
public class CleartextStorageDirect extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String creditCard = request.getParameter("creditCard");
        String userId = request.getParameter("userId");
        response.setContentType("application/json");

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "UPDATE users SET credit_card = ? WHERE id = ?")) {

            // VULN: Storing credit card number as plaintext in database
            ps.setString(1, creditCard);
            ps.setString(2, userId);
            ps.executeUpdate();

            response.getWriter().println("{\"status\": \"payment info saved\"}");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
