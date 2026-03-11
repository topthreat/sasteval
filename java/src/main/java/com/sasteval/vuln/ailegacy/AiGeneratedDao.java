package com.sasteval.vuln.ailegacy;

import com.sasteval.util.DbUtil;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CWE-89: SQL Injection (AI-Generated DAO pattern)
 * VULNERABILITY: All CRUD methods use string concatenation for SQL queries.
 * Simulates typical AI-generated data-access code that lacks parameterized queries.
 */
public class AiGeneratedDao {

    public void insertUser(String name, String email) throws SQLException {
        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            // VULN: String concatenation in INSERT
            String sql = "INSERT INTO users (username, email) VALUES ('" + name + "', '" + email + "')";
            stmt.executeUpdate(sql);
        }
    }

    public List<Map<String, String>> getUserByName(String name) throws SQLException {
        List<Map<String, String>> results = new ArrayList<>();
        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            // VULN: String concatenation in SELECT
            String sql = "SELECT * FROM users WHERE username = '" + name + "'";
            ResultSet rs = stmt.executeQuery(sql);
            while (rs.next()) {
                Map<String, String> row = new HashMap<>();
                row.put("id", String.valueOf(rs.getInt("id")));
                row.put("username", rs.getString("username"));
                row.put("email", rs.getString("email"));
                results.add(row);
            }
        }
        return results;
    }

    public void updateUserEmail(String name, String email) throws SQLException {
        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            // VULN: String concatenation in UPDATE
            String sql = "UPDATE users SET email = '" + email + "' WHERE username = '" + name + "'";
            stmt.executeUpdate(sql);
        }
    }

    public void deleteUser(String name) throws SQLException {
        try (Connection conn = DbUtil.getConnection();
             Statement stmt = conn.createStatement()) {
            // VULN: String concatenation in DELETE
            String sql = "DELETE FROM users WHERE username = '" + name + "'";
            stmt.executeUpdate(sql);
        }
    }
}
