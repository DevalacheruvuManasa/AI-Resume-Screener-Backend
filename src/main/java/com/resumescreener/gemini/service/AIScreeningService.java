package com.resumescreener.gemini.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.resumescreener.gemini.model.Candidate;
import com.resumescreener.gemini.model.User; // <-- Import the User model
import com.resumescreener.gemini.repository.CandidateRepository;
import com.resumescreener.gemini.repository.UserRepository; // <-- Import the UserRepository
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.security.Principal; // <-- Import the Principal object for user identity
import java.util.List;
import java.util.Map;

@Service
public class AIScreeningService {

    @Autowired
    private CandidateRepository candidateRepository;

    // --- NEW DEPENDENCY ---
    // We need the UserRepository to find the User's ID from their username.
    @Autowired
    private UserRepository userRepository;

    private final WebClient webClient;
    private final String groqApiUrl;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    public AIScreeningService(WebClient.Builder webClientBuilder,
                              @Value("${groq.api.url}") String groqApiUrl,
                              @Value("${groq.api.key}") String groqApiKey) {
        this.groqApiUrl = groqApiUrl;
        this.webClient = webClientBuilder
                .defaultHeader("Authorization", "Bearer " + groqApiKey)
                .build();
    }

    /**
     * Main screening method, now updated to associate the screening with a user.
     * @param principal Automatically injected by Spring Security, contains the logged-in user's name.
     */
    // --- UPDATED METHOD SIGNATURE ---
    public Candidate screen(MultipartFile resumeFile, String jobDescription, Principal principal) throws IOException {
        String resumeText = extractTextFromPdf(resumeFile);

        String systemPrompt = "You are an expert HR assistant. Your task is to analyze a resume against a job description. Respond ONLY with a valid JSON object. Do not add any text, explanations, or markdown formatting before or after the JSON block. The JSON object must have three keys: 'candidateName', 'score' (an integer from 0-100), and 'feedback' (a short 2-3 sentence string).";
        String userPrompt = "JOB DESCRIPTION:\n" + jobDescription + "\n\nRESUME TEXT:\n" + resumeText;

        Map<String, Object> requestBody = Map.of(
            "model", "llama3-8b-8192",
            "messages", List.of(
                Map.of("role", "system", "content", systemPrompt),
                Map.of("role", "user", "content", userPrompt)
            ),
            "temperature", 0.3,
            "response_format", Map.of("type", "json_object")
        );

        String responseJsonString = webClient.post()
                .uri(groqApiUrl)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(requestBody)
                .retrieve()
                .bodyToMono(String.class)
                .block();

        JsonNode rootNode = objectMapper.readTree(responseJsonString);
        String jsonContent = rootNode.path("choices").get(0).path("message").path("content").asText();
        JsonNode aiResponse;
        try {
            aiResponse = objectMapper.readTree(jsonContent);
        } catch (IOException e) {
            throw new IOException("AI returned a non-JSON response: " + jsonContent, e);
        }

        // --- NEW LOGIC: Find the logged-in user ---
        User user = userRepository.findByUsername(principal.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found in database, which should not happen."));

        // Create the candidate object
        Candidate candidate = new Candidate();
        // --- NEW LOGIC: Associate the candidate with the user ---
        candidate.setUserId(user.getId());
        
        candidate.setOriginalFileName(resumeFile.getOriginalFilename());
        candidate.setResumeText(resumeText);
        candidate.setJobDescription(jobDescription);

        // Robust data mapping logic
        String name = aiResponse.path("candidateName").asText("Extraction Failed");
        int score = aiResponse.path("score").asInt(0);
        String feedback = aiResponse.path("feedback").asText("AI did not provide feedback.");

        candidate.setCandidateName(name);
        candidate.setScore(score);
        candidate.setFeedback(feedback);

        return candidateRepository.save(candidate);
    }

    /**
     * Extracts all text from an uploaded PDF file.
     */
    private String extractTextFromPdf(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("The uploaded file is empty. Please select a valid PDF.");
        }

        byte[] fileBytes = file.getBytes();

        try (PDDocument document = Loader.loadPDF(fileBytes)) {
            if (document.isEncrypted()) {
                throw new IOException("The PDF file is encrypted and cannot be read.");
            }
            PDFTextStripper stripper = new PDFTextStripper();
            return stripper.getText(document);
        } catch (IOException e) {
            System.err.println("Failed to parse PDF: " + file.getOriginalFilename());
            e.printStackTrace();
            throw new IOException("Could not read the PDF. It may be corrupted.", e);
        }
    }
}