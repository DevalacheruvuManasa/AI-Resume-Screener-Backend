// File: src/main/java/com/resumescreener/gemini/model/Candidate.java
package com.resumescreener.gemini.model;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document(collection = "candidates")
public class Candidate {
    @Id
 private String id;
    
    // --- ADD THIS NEW FIELD ---
    private String userId; // This will store the ID of the User who submitted this.
    
    private String originalFileName;
    private String resumeText;
    private String jobDescription;
    private Integer score;
    private String feedback;
    private String candidateName;
}