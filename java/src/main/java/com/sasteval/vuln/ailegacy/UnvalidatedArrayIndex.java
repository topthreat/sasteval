package com.sasteval.vuln.ailegacy;

import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;

/**
 * CWE-129: Improper Validation of Array Index
 * VULNERABILITY: User-controlled index selects a dangerous internal admin action.
 */
public class UnvalidatedArrayIndex extends HttpServlet {

    private static final String[] ADMIN_ACTIONS = {
            "UPDATE users SET role = 'user' WHERE id = 2",
            "DELETE FROM users WHERE id = 1",
            "UPDATE users SET password = 'reset-required' WHERE id = 3"
    };

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String indexParam = request.getParameter("index");
        response.setContentType("application/json");

        // VULN: User-supplied index selects which privileged action to execute.
        int index = Integer.parseInt(indexParam);
        String sql = ADMIN_ACTIONS[index];

        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            int rows = stmt.executeUpdate(sql);
            response.getWriter().println("{\"actionIndex\": " + index + ", \"rows\": " + rows + "}");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
