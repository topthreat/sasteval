package com.sasteval.vuln.medium;

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
 * CWE-89: SQL Injection (Multi-Param Cross-Method)
 * VULNERABILITY: Two user inputs flow through a helper method into a concatenated SQL query.
 */
public class SqlInjectionMultiStep extends HttpServlet {

    private final Gson gson = new Gson();

    private String buildQuery(String table, String filter) {
        // VULN: Multiple user inputs concatenated into SQL query
        return "SELECT * FROM " + table + " WHERE status = '" + filter + "'";
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String table = request.getParameter("table");
        String filter = request.getParameter("filter");
        response.setContentType("application/json");

        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {

            String query = buildQuery(table, filter);
            ResultSet rs = stmt.executeQuery(query);

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                for (int i = 1; i <= rs.getMetaData().getColumnCount(); i++) {
                    row.put(rs.getMetaData().getColumnName(i), rs.getObject(i));
                }
                results.add(row);
            }

            response.getWriter().println(gson.toJson(results));

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"" + e.getMessage() + "\"}");
        }
    }
}
