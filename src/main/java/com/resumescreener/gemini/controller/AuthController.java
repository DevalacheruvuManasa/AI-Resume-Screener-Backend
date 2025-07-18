package com.resumescreener.gemini.controller;

import com.resumescreener.gemini.model.User;
import com.resumescreener.gemini.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
// Remember to configure global CORS in your SecurityConfig for production readiness
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true") 
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Handles new user registration.
     * It now accepts a RegistrationRequest object instead of a generic Map.
     * @param registrationRequest The JSON body containing username and password.
     * @return A success or error message.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest registrationRequest) {
        // Check if the username is already taken
        if (userRepository.findByUsername(registrationRequest.getUsername()).isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("message", "Error: Username is already taken!"));
        }

        // Create a new user and hash the password
        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    /**
     * An endpoint for the frontend to check if a user is currently logged in
     * and to get their details.
     * @param principal Automatically injected by Spring Security if the user is authenticated.
     * @return A map containing the username of the logged-in user, or an unauthorized error.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Principal principal) {
        if (principal == null) {
            // This case shouldn't be hit if Spring Security is configured correctly,
            // but it's a good safeguard.
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        // The principal's name is the username of the authenticated user.
        return ResponseEntity.ok(Map.of("username", principal.getName()));
    }

    // NOTE: We do NOT need a @PostMapping("/login") method here.
    // Spring Security's formLogin() feature automatically creates and handles
    // the /api/auth/login endpoint for us. Our job is just to configure it
    // correctly in SecurityConfig.java.
}