// File: src/main/java/com/resumescreener/gemini/controller/ScreeningController.java
package com.resumescreener.gemini.controller;

import com.resumescreener.gemini.model.Candidate;
import com.resumescreener.gemini.model.User;
import com.resumescreener.gemini.repository.CandidateRepository;
import com.resumescreener.gemini.repository.UserRepository;
import com.resumescreener.gemini.service.AIScreeningService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.Principal;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ScreeningController {

    @Autowired
    private AIScreeningService screeningService;

    @Autowired
    private CandidateRepository candidateRepository;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/candidates")
    public ResponseEntity<List<Candidate>> getAllCandidates(Principal principal) {
        User user = userRepository.findByUsername(principal.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found."));
        List<Candidate> candidates = candidateRepository.findByUserIdOrderByScoreDesc(user.getId());
        return ResponseEntity.ok(candidates);
    }

    @PostMapping("/screen")
    public ResponseEntity<?> screenResume(@RequestParam("resume") MultipartFile resume,
                                          @RequestParam("jobDescription") String jobDescription,
                                          Principal principal) {
        try {
            Candidate newCandidate = screeningService.screen(resume, jobDescription, principal);
            return new ResponseEntity<>(newCandidate, HttpStatus.CREATED);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of("message", e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("message", "An internal error occurred."));
        }
    }
}