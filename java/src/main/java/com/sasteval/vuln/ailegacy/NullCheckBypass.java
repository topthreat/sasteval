package com.sasteval.vuln.ailegacy;

import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * CWE-754: Improper Check for Exceptional Conditions
 * VULNERABILITY: Null handling fails open and reaches an admin-only delete operation.
 */
public class NullCheckBypass extends HttpServlet {

    private boolean canDeleteUser(String token) {
        try {
            int prefixLength = token.length();
            return prefixLength > 10 && token.startsWith("admin-");
        } catch (NullPointerException e) {
            // VULN: Missing token unexpectedly grants access instead of denying it.
            return true;
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String token = request.getHeader("X-Admin-Token");
        String userId = request.getParameter("userId");
        response.setContentType("application/json");

        if (!canDeleteUser(token)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().println("{\"error\": \"Admin token required\"}");
            return;
        }

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE id = ?")) {
            ps.setString(1, userId);
            int rows = ps.executeUpdate();
            response.getWriter().println("{\"deleted\": " + rows + "}");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
