package com.sasteval.vuln.hard;

import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;

/**
 * CWE-611: XXE (Cross-File Helper - XML Processor)
 * Part of a 2-file taint chain: XxeCrossFile -> XmlProcessor.
 */
public class XmlProcessor {

    public Document processXml(InputStream input) throws Exception {
        // VULN: DocumentBuilderFactory with default settings allows external entities
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(input);
    }
}
