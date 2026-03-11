package com.sasteval.safe;

import com.sasteval.util.DbUtil;
import com.sasteval.vuln.hard.RequestParser;
import com.sasteval.vuln.hard.UserInputDto;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;

/**
 * TRUE NEGATIVE for CWE-306: Missing Authentication
 * SAFE: Authorization uses trusted server-side session state rather than client input.
 */
public class SafeAuthzFromSession extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        UserInputDto dto = RequestParser.parseRequest(request);
        HttpSession session = request.getSession();
        if (session.getAttribute("role") == null) {
            session.setAttribute("role", "user");
        }

        String sessionRole = String.valueOf(session.getAttribute("role"));
        if (!"admin".equals(sessionRole)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().println("{\"error\": \"Admin role required\"}");
            return;
        }

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE id = ?")) {

            // SAFE: Authorization is based on trusted session state only.
            ps.setString(1, dto.getUserId());
            int rows = ps.executeUpdate();
            response.setContentType("application/json");
            response.getWriter().println("{\"sessionRole\": \"" + sessionRole + "\", \"deleted\": " + rows + "}");
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
