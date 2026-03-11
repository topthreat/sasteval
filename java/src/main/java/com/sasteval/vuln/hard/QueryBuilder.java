package com.sasteval.vuln.hard;

/**
 * CWE-89: SQL Injection (Cross-File Helper - Query Builder)
 * Part of a 3-file taint chain: SqlInjectionCrossFile -> QueryBuilder -> QueryExecutor.
 */
public class QueryBuilder {

    public String buildUserQuery(String userId) {
        // VULN: User input concatenated into SQL query string
        return "SELECT * FROM users WHERE id = '" + userId + "'";
    }
}
