package com.sasteval.vuln.ailegacy;

import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * CWE-501: Trust Boundary Violation
 * VULNERABILITY: Untrusted user input is promoted into trusted session state and
 * immediately used to authorize an admin-only delete operation.
 */
public class TrustBoundaryViolation extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String role = request.getParameter("role");
        String userId = request.getParameter("userId");
        response.setContentType("application/json");

        HttpSession session = request.getSession();

        // VULN: User-controlled input stored directly in trusted session scope
        session.setAttribute("role", role);

        if ("admin".equals(session.getAttribute("role"))) {
            try (Connection conn = DbUtil.getConnection();
                 PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE id = ?")) {
                ps.setString(1, userId);
                int rows = ps.executeUpdate();
                response.getWriter().println("{\"sessionRole\": \"" + role + "\", \"deleted\": " + rows + "}");
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
            }
            return;
        }

        response.getWriter().println("{\"sessionRole\": \"" + role + "\", \"status\": \"no admin action\"}");
    }
}
