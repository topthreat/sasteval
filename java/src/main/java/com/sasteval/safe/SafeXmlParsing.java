package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import org.w3c.dom.Document;

/**
 * TRUE NEGATIVE for CWE-611: XML External Entity (XXE)
 * SAFE: Disables external entities and DTDs before parsing.
 */
public class SafeXmlParsing extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/xml");

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // SAFE: Disable external entities and DTDs
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(request.getInputStream());

            String rootElement = doc.getDocumentElement().getTagName();
            response.getWriter().println("<result>Parsed root element: " + rootElement + "</result>");

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("<error>Parse failed</error>");
        }
    }
}
