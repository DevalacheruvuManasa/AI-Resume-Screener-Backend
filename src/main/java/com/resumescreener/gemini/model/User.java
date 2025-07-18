package com.resumescreener.gemini.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "users")
public class User {
    @Id
    private String id;

    @Indexed(unique = true) // Ensure usernames are unique
    private String username;
    
    private String password; // This will store the HASHED password
}