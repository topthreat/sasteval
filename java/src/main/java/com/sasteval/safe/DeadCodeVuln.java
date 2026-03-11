package com.sasteval.safe;

import com.google.gson.Gson;
import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TRUE NEGATIVE for CWE-89: SQL Injection
 * SAFE: The public doGet uses PreparedStatement. The vulnerable code in neverCalled()
 * is dead code that is never invoked from any path.
 */
public class DeadCodeVuln extends HttpServlet {

    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String id = request.getParameter("id");
        response.setContentType("application/json");

        try (Connection conn = DbUtil.getConnection();
             PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {

            // SAFE: Parameterized query
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                results.add(row);
            }

            response.getWriter().println(gson.toJson(results));

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }

    /**
     * DEAD CODE: This method is never called from anywhere.
     * Contains SQL injection but is unreachable.
     */
    private void neverCalled() {
        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            String input = "unreachable";
            String sql = "SELECT * FROM users WHERE username = '" + input + "'";
            stmt.executeQuery(sql);
        } catch (Exception e) {
            // dead code
        }
    }
}
