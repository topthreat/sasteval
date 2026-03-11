package com.sasteval.sca;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.core.joran.spi.JoranException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * SCA Reachability: CVE-2024-12798 is REACHABLE.
 * The benchmark calls JoranConfigurator.doConfigure() with a user-controlled
 * config path, which is a reasonable reachability signal for the vulnerable
 * package. Exploitability still depends on the referenced configuration content.
 */
public class LogbackReachable extends HttpServlet {

    public void configureLogging(String configPath) throws JoranException {
        LoggerContext context = new LoggerContext();
        JoranConfigurator configurator = new JoranConfigurator();
        configurator.setContext(context);
        context.reset();
        // REACHABLE: Calls vulnerable doConfigure with user input
        configurator.doConfigure(configPath);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String logConfig = request.getParameter("logConfig");
        response.setContentType("application/json");

        try {
            configureLogging(logConfig);
            response.getWriter().println("{\"status\": \"Logging reconfigured\"}");
        } catch (JoranException e) {
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().println("{\"error\": \"Configuration failed: " + e.getMessage() + "\"}");
        }
    }
}
