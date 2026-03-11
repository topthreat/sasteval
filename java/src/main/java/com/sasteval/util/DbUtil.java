package com.sasteval.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class DbUtil {

    private static final String JDBC_URL = "jdbc:h2:mem:sasteval;DB_CLOSE_DELAY=-1";
    private static final String JDBC_USER = "sa";
    private static final String JDBC_PASS = "";

    static {
        try {
            Class.forName("org.h2.Driver");
            initSchema();
        } catch (ClassNotFoundException | SQLException e) {
            throw new RuntimeException("Failed to initialize database", e);
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(JDBC_URL, JDBC_USER, JDBC_PASS);
    }

    public static void initSchema() throws SQLException {
        try (Connection conn = DriverManager.getConnection(JDBC_URL, JDBC_USER, JDBC_PASS);
             Statement stmt = conn.createStatement()) {

            stmt.execute("CREATE TABLE IF NOT EXISTS users ("
                    + "id INT PRIMARY KEY, "
                    + "username VARCHAR(255), "
                    + "email VARCHAR(255), "
                    + "password VARCHAR(255), "
                    + "role VARCHAR(50)"
                    + ")");

            stmt.execute("CREATE TABLE IF NOT EXISTS products ("
                    + "id INT PRIMARY KEY, "
                    + "name VARCHAR(255), "
                    + "price DECIMAL(10,2)"
                    + ")");

            stmt.execute("CREATE TABLE IF NOT EXISTS orders ("
                    + "id INT PRIMARY KEY, "
                    + "user_id INT, "
                    + "product_id INT"
                    + ")");

            stmt.execute("CREATE TABLE IF NOT EXISTS comments ("
                    + "id INT AUTO_INCREMENT PRIMARY KEY, "
                    + "comment VARCHAR(4000)"
                    + ")");
        }
    }
}
