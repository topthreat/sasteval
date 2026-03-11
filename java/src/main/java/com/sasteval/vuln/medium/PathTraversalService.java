package com.sasteval.vuln.medium;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * CWE-22: Path Traversal
 * VULNERABILITY: User input is used to construct file path without canonicalization.
 */
public class PathTraversalService extends HttpServlet {

    private File resolvePath(String userInput) {
        return new File("/data/uploads/" + userInput);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String file = request.getParameter("file");

        // VULN: Path traversal via unvalidated user input
        File resolved = resolvePath(file);

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + resolved.getName() + "\"");

        try (FileInputStream fis = new FileInputStream(resolved);
             OutputStream out = response.getOutputStream()) {

            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }

        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            response.getWriter().println("{\"error\": \"File not found\"}");
        }
    }
}
