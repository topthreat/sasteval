package com.sasteval.vuln.hard;

import com.google.gson.Gson;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CWE-89: SQL Injection (Cross-File Taint Chain)
 * VULNERABILITY: User input flows through QueryBuilder and QueryExecutor across 3 files.
 */
public class SqlInjectionCrossFile extends HttpServlet {

    private final Gson gson = new Gson();
    private final QueryBuilder queryBuilder = new QueryBuilder();
    private final QueryExecutor queryExecutor = new QueryExecutor();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userId = request.getParameter("userId");
        response.setContentType("application/json");

        try {
            // VULN: Tainted input flows through QueryBuilder -> QueryExecutor
            String sql = queryBuilder.buildUserQuery(userId);
            ResultSet rs = queryExecutor.executeQuery(sql);

            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("id", rs.getInt("id"));
                row.put("username", rs.getString("username"));
                row.put("email", rs.getString("email"));
                results.add(row);
            }

            response.getWriter().println(gson.toJson(results));

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"Query failed\"}");
        }
    }
}
