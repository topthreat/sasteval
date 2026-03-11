package com.sasteval.vuln.hard;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.w3c.dom.Document;

/**
 * CWE-611: XXE (Cross-File Taint Chain)
 * VULNERABILITY: XML input flows to XmlProcessor which parses without disabling external entities.
 */
public class XxeCrossFile extends HttpServlet {

    private final XmlProcessor xmlProcessor = new XmlProcessor();

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/xml");

        try {
            // VULN: Request body passed to insecure XML parser in separate class
            Document doc = xmlProcessor.processXml(request.getInputStream());

            String rootElement = doc.getDocumentElement().getTagName();
            response.getWriter().println("<result>Parsed root element: " + rootElement + "</result>");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("<error>" + e.getMessage() + "</error>");
        }
    }
}
