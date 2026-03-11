package com.sasteval.vuln.hard;

import javax.servlet.http.HttpServletRequest;

/**
 * Utility class that parses HTTP request parameters into a UserInputDto.
 */
public class RequestParser {

    public static UserInputDto parseRequest(HttpServletRequest req) {
        UserInputDto dto = new UserInputDto();
        dto.setPayload(req.getParameter("payload"));
        dto.setUserId(req.getParameter("userId"));
        dto.setRole(req.getParameter("role"));
        return dto;
    }
}
