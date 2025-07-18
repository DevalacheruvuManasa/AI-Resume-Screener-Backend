package com.resumescreener.gemini.config;

import com.resumescreener.gemini.service.MongoUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MongoUserDetailsService userDetailsService;

    /**
     * This bean provides the password hashing algorithm (BCrypt).
     * It's used for both registering users and authenticating them.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * This bean configures the "brain" of the authentication process.
     * It tells Spring Security how to find users and how to check their passwords.
     */
    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
        
        authenticationManagerBuilder.userDetailsService(userDetailsService)
                                    .passwordEncoder(passwordEncoder());
        
        return authenticationManagerBuilder.build();
    }

    /**
     * This bean configures all the HTTP security rules for our application.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Use the global CORS configuration defined below
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            
            // Disable CSRF protection, as it's not typically used for stateless APIs consumed by SPAs
            .csrf(csrf -> csrf.disable())
            
            // --- THIS IS THE KEY FIX FOR API-DRIVEN APPS ---
            .exceptionHandling(exceptions -> exceptions
                // When an unauthenticated user tries to access a protected resource,
                // this entry point is triggered. Instead of redirecting, it simply
                // returns a 401 Unauthorized status code.
                .authenticationEntryPoint((request, response, authException) -> 
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")
                )
            )
            // Configure the authorization rules for different endpoints
            .authorizeHttpRequests(auth -> auth
                // Allow public access to registration and login endpoints
                .requestMatchers(HttpMethod.POST, "/api/auth/register", "/api/auth/login").permitAll()
                
                // Allow public access to the /me endpoint to check auth status
                .requestMatchers(HttpMethod.GET, "/api/auth/me").permitAll()
                
                // All other API endpoints under /api/ must be authenticated
                .requestMatchers("/api/**").authenticated()
                
                // Any other request that doesn't match the rules above is permitted.
                // This is useful for allowing the initial HTML/JS/CSS of the React app to load.
                .anyRequest().permitAll()
            )
            // Configure the built-in form login to handle the authentication process
            .formLogin(formLogin -> formLogin
                .loginProcessingUrl("/api/auth/login") // This is the URL Spring Security will listen to
                .successHandler((request, response, authentication) -> {
                    // On successful login, send back a 200 OK with a success message
                    response.setStatus(HttpServletResponse.SC_OK);
                    response.getWriter().write("{\"message\": \"Login successful!\"}");
                    response.getWriter().flush();
                })
                .failureHandler((request, response, exception) -> {
                    // On failed login, send back a 401 Unauthorized status
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid username or password");
                })
            )
            // Configure the logout process
            .logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler((request, response, authentication) -> 
                    response.setStatus(HttpServletResponse.SC_OK)
                )
                .deleteCookies("JSESSIONID") // Invalidate the session cookie
                .invalidateHttpSession(true)
            );

        return http.build();
    }
    
    /**
     * This bean provides a global CORS configuration for the entire application.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow requests from your React development server
        configuration.setAllowedOrigins(List.of("http://localhost:5173"));
        // Allow all standard HTTP methods
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Allow specific headers required for modern web apps
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        // This is crucial for session cookies to be sent back and forth
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // Apply this configuration to all paths in your application
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}