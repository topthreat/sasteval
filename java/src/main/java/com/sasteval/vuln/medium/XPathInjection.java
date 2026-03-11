package com.sasteval.vuln.medium;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;
import java.io.File;
import java.io.IOException;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

/**
 * CWE-643: XPath Injection (Cross-Method)
 * VULNERABILITY: User input is concatenated into XPath expression.
 */
public class XPathInjection extends HttpServlet {

    private NodeList queryXml(String input) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(new File("/data/users.xml"));

        XPath xpath = XPathFactory.newInstance().newXPath();

        // VULN: User input concatenated into XPath expression
        String expression = "//users/user[@name='" + input + "']/password";
        return (NodeList) xpath.evaluate(expression, doc, XPathConstants.NODESET);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        response.setContentType("application/json");

        try {
            NodeList results = queryXml(username);
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < results.getLength(); i++) {
                sb.append("\"").append(results.item(i).getTextContent()).append("\",");
            }
            if (sb.length() > 1) sb.setLength(sb.length() - 1);
            sb.append("]");
            response.getWriter().println(sb.toString());

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"XPath query failed\"}");
        }
    }
}
