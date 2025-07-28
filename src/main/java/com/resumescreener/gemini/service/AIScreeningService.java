// File: src/main/java/com/resumescreener/gemini/service/AIScreeningService.java
package com.resumescreener.gemini.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.resumescreener.gemini.model.Candidate;
import com.resumescreener.gemini.model.User;
import com.resumescreener.gemini.repository.CandidateRepository;
import com.resumescreener.gemini.repository.UserRepository;
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
import java.security.Principal;
import java.util.List;
import java.util.Map;

@Service
public class AIScreeningService {

    @Autowired
    private CandidateRepository candidateRepository;
    
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

    public Candidate screen(MultipartFile resumeFile, String jobDescription, Principal principal) throws IOException {
        User user = userRepository.findByUsername(principal.getName())
            .orElseThrow(() -> new RuntimeException("Authenticated user not found."));
            
        String resumeText = extractTextFromPdf(resumeFile);
        String systemPrompt = "You are an expert HR assistant... Respond ONLY with a valid JSON object with keys: 'candidateName', 'score', and 'feedback'.";
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

        String responseJsonString = webClient.post().uri(groqApiUrl).contentType(MediaType.APPLICATION_JSON)
            .bodyValue(requestBody).retrieve().bodyToMono(String.class).block();

        JsonNode rootNode = objectMapper.readTree(responseJsonString);
        String jsonContent = rootNode.path("choices").get(0).path("message").path("content").asText();
        JsonNode aiResponse = objectMapper.readTree(jsonContent);

        Candidate candidate = new Candidate();
        candidate.setUserId(user.getId()); // <-- Associate with user
        candidate.setOriginalFileName(resumeFile.getOriginalFilename());
        candidate.setResumeText(resumeText);
        candidate.setJobDescription(jobDescription);
        candidate.setCandidateName(aiResponse.path("candidateName").asText("N/A"));
        candidate.setScore(aiResponse.path("score").asInt(0));
        candidate.setFeedback(aiResponse.path("feedback").asText("No feedback provided."));

        return candidateRepository.save(candidate);
    }
    
    private String extractTextFromPdf(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("The uploaded file is empty.");
        }
        byte[] fileBytes = file.getBytes();
        try (PDDocument document = Loader.loadPDF(fileBytes)) {
            if (document.isEncrypted()) {
                throw new IOException("The PDF file is encrypted.");
            }
            return new PDFTextStripper().getText(document);
        } catch (IOException e) {
            throw new IOException("Could not read the PDF file. It may be corrupted.", e);
        }
    }
}