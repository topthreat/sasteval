package com.sasteval.safe;

import com.google.gson.Gson;
import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * TRUE NEGATIVE for CWE-89: SQL Injection
 * SAFE: SQL is built from hardcoded internal configuration values, NOT from user input.
 */
public class InternalDataQuery extends HttpServlet {

    private static final Map<String, String> CONFIG = Map.of(
            "defaultRole", "user",
            "activeStatus", "active"
    );

    private final Gson gson = new Gson();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");

        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {

            // SAFE: Values come from hardcoded CONFIG map, not user input
            String query = "SELECT * FROM users WHERE role = '" + CONFIG.get("defaultRole") + "'";
            ResultSet rs = stmt.executeQuery(query);

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                row.put("role", rs.getString("role"));
                results.add(row);
            }

            response.getWriter().println(gson.toJson(results));

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
