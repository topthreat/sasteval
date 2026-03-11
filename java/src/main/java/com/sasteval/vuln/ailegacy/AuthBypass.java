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
 * CWE-306: Missing Authentication for Critical Function
 * VULNERABILITY: Admin-only destructive action relies on a client-supplied request parameter.
 */
public class AuthBypass extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        String targetUserId = request.getParameter("userId");
        HttpSession session = request.getSession();
        if (session.getAttribute("authenticated") == null) {
            session.setAttribute("authenticated", Boolean.FALSE);
        }

        // VULN: The handler has a server-side auth state but ignores it and trusts isAdmin from the request.
        if ("true".equals(request.getParameter("isAdmin"))) {
            try (Connection conn = DbUtil.getConnection();
                 PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE id = ?")) {

                ps.setString(1, targetUserId);
                int rows = ps.executeUpdate();
                response.getWriter().println("{\"deleted\": " + rows + ", \"authenticated\": "
                        + session.getAttribute("authenticated") + "}");
            } catch (Exception e) {
                response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
            }
        } else {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().println("{\"error\": \"Admin access required\"}");
        }
    }
}
