package com.resumescreener.gemini.controller;

import lombok.Data;

@Data
public class RegistrationRequest {
    private String username;
    private String password;
}