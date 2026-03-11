package com.sasteval.vuln.easy;

import com.sasteval.util.DbUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;

/**
 * CWE-209: Information Exposure Through an Error Message (Direct)
 * VULNERABILITY: Full stack trace is written to HTTP response.
 */
public class ErrorInfoLeakDirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String id = request.getParameter("id");
        response.setContentType("text/plain");

        try {
            Connection conn = DbUtil.getConnection();
            Statement stmt = conn.createStatement();
            stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
        } catch (Exception e) {
            // VULN: Full stack trace sent to client, leaking internal details
            e.printStackTrace(response.getWriter());
        }
    }
}
