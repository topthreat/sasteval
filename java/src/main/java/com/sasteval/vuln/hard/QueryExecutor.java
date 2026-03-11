package com.sasteval.vuln.hard;

import com.sasteval.util.DbUtil;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * CWE-89: SQL Injection (Cross-File Helper - Query Executor)
 * Part of a 3-file taint chain: SqlInjectionCrossFile -> QueryBuilder -> QueryExecutor.
 */
public class QueryExecutor {

    public ResultSet executeQuery(String sql) throws SQLException {
        // VULN: Executes query string without parameterization
        Connection conn = DbUtil.getConnection();
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
