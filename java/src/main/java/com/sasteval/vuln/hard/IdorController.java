package com.sasteval.vuln.hard;

import com.google.gson.Gson;
import com.sasteval.util.DbUtil;

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
 * CWE-639: Insecure Direct Object Reference (IDOR)
 * VULNERABILITY (horizontal): userId from request is used without verifying session ownership.
 * VULNERABILITY (vertical): role from request is trusted for authorization decisions.
 */
public class IdorController extends HttpServlet {

    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        UserInputDto dto = RequestParser.parseRequest(request);
        response.setContentType("application/json");
        HttpSession session = request.getSession();
        if (session.getAttribute("userId") == null) {
            session.setAttribute("userId", "2");
        }
        String sessionUserId = String.valueOf(session.getAttribute("userId"));

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement(
                     "SELECT id, username, email, password, role FROM users WHERE id = ?")) {

            // VULN (horizontal IDOR): The handler has a real session user,
            // but still returns another user's profile based only on the requested object ID.
            ps.setString(1, dto.getUserId());
            ResultSet rs = ps.executeQuery();

            if (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("sessionUserId", sessionUserId);
                user.put("requestedUserId", dto.getUserId());
                user.put("id", rs.getInt("id"));
                user.put("username", rs.getString("username"));
                user.put("email", rs.getString("email"));
                user.put("password", rs.getString("password"));
                user.put("role", rs.getString("role"));
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

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        UserInputDto dto = RequestParser.parseRequest(request);
        response.setContentType("application/json");
        HttpSession session = request.getSession();
        if (session.getAttribute("role") == null) {
            session.setAttribute("role", "user");
        }
        String sessionRole = String.valueOf(session.getAttribute("role"));

        // VULN (vertical IDOR): Authorization is based on the client's requested role,
        // not the server-side session role.
        if ("admin".equals(dto.getRole())) {
            try (Connection conn = DbUtil.getConnection();
                 PreparedStatement ps = conn.prepareStatement("DELETE FROM users WHERE id = ?")) {

                ps.setString(1, dto.getUserId());
                int rows = ps.executeUpdate();
                response.getWriter().println("{\"sessionRole\": \"" + sessionRole
                        + "\", \"trustedRole\": \"" + dto.getRole()
                        + "\", \"deleted\": " + rows + "}");

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
