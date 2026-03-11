package com.sasteval.vuln.easy;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import org.w3c.dom.Document;

/**
 * CWE-611: Improper Restriction of XML External Entity Reference (Direct)
 * VULNERABILITY: XML parser does not disable external entities.
 */
public class XxeDirect extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/xml");

        try {
            // VULN: DocumentBuilderFactory with default settings allows external entities
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(request.getInputStream());

            String rootElement = doc.getDocumentElement().getTagName();
            response.getWriter().println("<result>Parsed root element: " + rootElement + "</result>");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("<error>" + e.getMessage() + "</error>");
        }
    }
}
