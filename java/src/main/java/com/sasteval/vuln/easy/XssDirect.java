package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * CWE-79: Cross-Site Scripting (Reflected, Direct)
 * VULNERABILITY: User input is reflected directly into HTML output without encoding.
 */
public class XssDirect extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String name = request.getParameter("name");
        response.setContentType("text/html");

        // VULN: Direct reflection of user input into HTML
        response.getWriter().println("<h1>Hello " + name + "</h1>");
    }
}
