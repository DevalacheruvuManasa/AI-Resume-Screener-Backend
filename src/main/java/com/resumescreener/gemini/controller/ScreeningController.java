package com.resumescreener.gemini.controller;

import com.resumescreener.gemini.model.Candidate;
import com.resumescreener.gemini.model.User; // <-- Import the User model
import com.resumescreener.gemini.repository.CandidateRepository;
import com.resumescreener.gemini.repository.UserRepository; // <-- Import the UserRepository
import com.resumescreener.gemini.service.AIScreeningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.Principal; // <-- Import the Principal object
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "http://localhost:5173", allowCredentials = "true")
public class ScreeningController {

    @Autowired
    private AIScreeningService screeningService;

    @Autowired
    private CandidateRepository candidateRepository;

    // --- NEW DEPENDENCY ---
    // We need the UserRepository to find the User object from the principal's name.
    @Autowired
    private UserRepository userRepository;

    /**
     * This endpoint now fetches candidates ONLY for the currently logged-in user.
     * @param principal Automatically injected by Spring Security, contains the user's identity.
     * @return A list of candidates belonging to the authenticated user.
     */
    @GetMapping("/candidates")
    public ResponseEntity<List<Candidate>> getAllCandidates(Principal principal) {
        // Find the full User object from the username provided by the security context.
        User user = userRepository.findByUsername(principal.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found in database."));
        
        // Use the new repository method to get candidates for this specific user ID.
        List<Candidate> candidates = candidateRepository.findByUserIdOrderByScoreDesc(user.getId());
        return ResponseEntity.ok(candidates);
    }

    /**
     * This endpoint now associates the new screening record with the logged-in user.
     * @param principal Automatically injected by Spring Security.
     */
    @PostMapping("/screen")
    public ResponseEntity<?> screenResume(@RequestParam("resume") MultipartFile resume,
                                          @RequestParam("jobDescription") String jobDescription,
                                          Principal principal) { // <-- The Principal is automatically provided
        try {
            // Pass the principal object to the service method so it knows who is making the request.
            Candidate newCandidate = screeningService.screen(resume, jobDescription, principal);
            return new ResponseEntity<>(newCandidate, HttpStatus.CREATED);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity
                    .status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("message", "An internal error occurred during analysis."));
        }
    }
}