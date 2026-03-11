package com.sasteval.vuln.hard;

/**
 * Simple POJO for carrying user input across layers.
 */
public class UserInputDto {

    private String payload;
    private String userId;
    private String role;

    public UserInputDto() {
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
