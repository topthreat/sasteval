package com.sasteval.util;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;

public class SanitizerUtil {

    private static final PolicyFactory POLICY = Sanitizers.FORMATTING;

    public static String sanitize(String html) {
        if (html == null) {
            return "";
        }
        return POLICY.sanitize(html);
    }
}
