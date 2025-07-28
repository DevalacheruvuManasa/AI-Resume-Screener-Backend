// File: src/main/java/com/resumescreener/gemini/dto/LoginRequest.java
package com.resumescreener.gemini.dto;
import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
}