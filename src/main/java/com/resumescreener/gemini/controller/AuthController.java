package com.resumescreener.gemini.controller;

import com.resumescreener.gemini.dto.RegistrationRequest;
import com.resumescreener.gemini.model.User;
import com.resumescreener.gemini.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // NOTE: We do NOT inject or use the AuthenticationManager here.
    // Spring Security's formLogin() filter handles the login process for us.

    /**
     * Handles new user registration. This endpoint is public.
     * @param registrationRequest The JSON body containing the new user's credentials.
     * @return A success or error message.
     */
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RegistrationRequest registrationRequest) {
        if (userRepository.findByUsername(registrationRequest.getUsername()).isPresent()) {
            return ResponseEntity
                    .badRequest()
                    .body(Map.of("message", "Error: Username is already taken!"));
        }

        User user = new User();
        user.setUsername(registrationRequest.getUsername());
        user.setPassword(passwordEncoder.encode(registrationRequest.getPassword()));
        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }

    /**
     * An endpoint for the frontend to check the current user's authentication status.
     * Spring Security ensures this can only be accessed if the user has a valid session.
     * @param principal Automatically injected by Spring Security if the user is authenticated.
     * @return A map containing the username of the logged-in user.
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Principal principal) {
        if (principal == null) {
            // This case is a safeguard, but the security filter should prevent it.
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }
        return ResponseEntity.ok(Map.of("username", principal.getName()));
    }
}