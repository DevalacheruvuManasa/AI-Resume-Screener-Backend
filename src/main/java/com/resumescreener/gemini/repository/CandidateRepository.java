// File: src/main/java/com/resumescreener/gemini/repository/CandidateRepository.java
package com.resumescreener.gemini.repository;

import com.resumescreener.gemini.model.Candidate;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface CandidateRepository extends MongoRepository<Candidate, String> {
    List<Candidate> findAllByOrderByScoreDesc();
    List<Candidate> findByUserIdOrderByScoreDesc(String userId);
}