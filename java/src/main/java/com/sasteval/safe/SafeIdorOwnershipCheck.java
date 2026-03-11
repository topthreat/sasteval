package com.sasteval.safe;

import com.google.gson.Gson;
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
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

/**
 * TRUE NEGATIVE for CWE-639: IDOR
 * SAFE: Access is restricted to the session owner's object unless the session role is admin.
 */
public class SafeIdorOwnershipCheck extends HttpServlet {

    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        UserInputDto dto = RequestParser.parseRequest(request);
        HttpSession session = request.getSession();
        if (session.getAttribute("userId") == null) {
            session.setAttribute("userId", "2");
        }
        if (session.getAttribute("role") == null) {
            session.setAttribute("role", "user");
        }

        String sessionUserId = String.valueOf(session.getAttribute("userId"));
        String sessionRole = String.valueOf(session.getAttribute("role"));

        if (!sessionUserId.equals(dto.getUserId()) && !"admin".equals(sessionRole)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().println("{\"error\": \"Ownership check failed\"}");
            return;
        }

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id, username, email, role FROM users WHERE id = ?")) {

            // SAFE: Request only succeeds when the session already owns the object
            // or the trusted session role is admin.
            ps.setString(1, dto.getUserId());
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("sessionUserId", sessionUserId);
                user.put("sessionRole", sessionRole);
                user.put("requestedUserId", dto.getUserId());
                user.put("id", rs.getInt("id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("role", rs.getString("role"));
                response.setContentType("application/json");
                response.getWriter().println(gson.toJson(user));
            } else {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                response.getWriter().println("{\"error\": \"User not found\"}");
            }
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
