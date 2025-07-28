// File: src/main/java/com/resumescreener/gemini/dto/RegistrationRequest.java
package com.resumescreener.gemini.dto;
import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private String password;
}