package com.sasteval.vuln.medium;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Hashtable;

/**
 * CWE-90: LDAP Injection (Cross-Method)
 * VULNERABILITY: User input is concatenated into LDAP search filter.
 */
public class LdapInjection extends HttpServlet {

    private NamingEnumeration<SearchResult> searchLdap(String username) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://localhost:389");

        DirContext ctx = new InitialDirContext(env);
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        // VULN: User input concatenated into LDAP filter without escaping
        String filter = "(uid=" + username + ")";
        return ctx.search("dc=example,dc=com", filter, controls);
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        String username = request.getParameter("username");
        response.setContentType("application/json");

        try {
            NamingEnumeration<SearchResult> results = searchLdap(username);
            StringBuilder sb = new StringBuilder("[");
            while (results.hasMore()) {
                SearchResult result = results.next();
                sb.append("\"").append(result.getNameInNamespace()).append("\",");
            }
            if (sb.length() > 1) sb.setLength(sb.length() - 1);
            sb.append("]");
            response.getWriter().println(sb.toString());

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().println("{\"error\": \"LDAP query failed\"}");
        }
    }
}
