package com.resumescreener.gemini.service;

import com.resumescreener.gemini.model.User;
import com.resumescreener.gemini.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

/**
 * This class is the bridge between Spring Security and our user data in MongoDB.
 * It implements the UserDetailsService interface, which has one method: loadUserByUsername.
 */
@Service
public class MongoUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    /**
     * Spring Security calls this method when a user tries to log in.
     * Our job is to find the user in our database and return their details
     * in a format that Spring Security understands (the UserDetails object).
     *
     * @param username The username submitted in the login form.
     * @return A UserDetails object containing the username, hashed password, and authorities.
     * @throws UsernameNotFoundException If the user does not exist in our database.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 1. Use our UserRepository to find the user by their username.
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));
        
        // 2. If the user is found, create and return a Spring Security User object.
        // This object needs the username, the HASHED password from the database,
        // and a list of roles/authorities (we can use an empty list for now).
        return new org.springframework.security.core.userdetails.User(
            user.getUsername(),
            user.getPassword(),
            new ArrayList<>() 
        );
    }
}