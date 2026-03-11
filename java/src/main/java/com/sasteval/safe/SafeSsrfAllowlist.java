package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

/**
 * TRUE NEGATIVE for CWE-918: SSRF
 * SAFE: Only HTTPS requests to allowlisted hosts are permitted.
 */
public class SafeSsrfAllowlist extends HttpServlet {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>();

    static {
        ALLOWED_HOSTS.add("status.example.com");
        ALLOWED_HOSTS.add("api.example.com");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String url = request.getParameter("url");
        if (url == null || url.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Missing url\"}");
            return;
        }

        URI uri = URI.create(url);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"URL not allowed\"}");
            return;
        }

        // SAFE: Outbound request is restricted to an allowlisted host and scheme.
        HttpURLConnection conn = (HttpURLConnection) new URL(uri.toString()).openConnection();
        conn.setRequestMethod("HEAD");
        conn.setConnectTimeout(1000);
        conn.setReadTimeout(1000);

        response.setContentType("application/json");
        response.getWriter().println("{\"allowedHost\": \"" + uri.getHost() + "\"}");
    }
}
