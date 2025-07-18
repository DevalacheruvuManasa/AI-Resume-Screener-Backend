package com.resumescreener.gemini.repository;

import com.resumescreener.gemini.model.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends MongoRepository<User, String> {
    // A custom method to find a user by their username
    Optional<User> findByUsername(String username);
}