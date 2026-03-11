package com.sasteval.safe;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * TRUE NEGATIVE for CWE-22: Path Traversal
 * SAFE: Canonical path must remain under the fixed uploads directory.
 */
public class SafePathTraversal extends HttpServlet {

    private static final File BASE_DIR = new File("/data/uploads");

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String file = request.getParameter("file");
        if (file == null || file.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Missing file\"}");
            return;
        }

        File canonicalBase = BASE_DIR.getCanonicalFile();
        File requested = new File(canonicalBase, file).getCanonicalFile();

        // SAFE: The resolved path must stay under the canonicalized base directory.
        if (!requested.getPath().startsWith(canonicalBase.getPath() + File.separator)) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Invalid file path\"}");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + requested.getName() + "\"");

        // SAFE: File read occurs only after canonical path enforcement.
        try (FileInputStream fis = new FileInputStream(requested);
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
