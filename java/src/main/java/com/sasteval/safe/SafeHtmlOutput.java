package com.sasteval.safe;

import com.sasteval.util.SanitizerUtil;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TRUE NEGATIVE for CWE-79: XSS
 * SAFE: User input is sanitized through SanitizerUtil before output.
 */
public class SafeHtmlOutput extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String userInput = request.getParameter("input");
        response.setContentType("text/html");

        // SAFE: Input is sanitized before rendering
        String sanitized = SanitizerUtil.sanitize(userInput);
        response.getWriter().println("<div>" + sanitized + "</div>");
    }
}
