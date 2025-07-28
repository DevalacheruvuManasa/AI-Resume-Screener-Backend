package com.resumescreener.gemini.config;

import com.resumescreener.gemini.service.MongoUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MongoUserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder =
            http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
        return authenticationManagerBuilder.build();
    }

    /**
     * This bean is essential for making login sessions work across different subdomains
     * on your deployed site (e.g., frontend.onrender.com and backend.onrender.com).
     */
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        // This regex allows the browser to share the session cookie between your Render subdomains.
        serializer.setDomainNamePattern("^.+?\\.onrender\\.com$"); 
        serializer.setSameSite("None"); // Required for modern browsers to accept cross-site cookies.
        serializer.setUseSecureCookie(true); // Ensures the cookie is only ever sent over secure HTTPS.
        return serializer;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Use the global CORS configuration defined in the corsConfigurationSource bean below.
            .cors(withDefaults())
            // Disable CSRF, which is standard for stateless APIs consumed by JavaScript frontends.
            .csrf(csrf -> csrf.disable())
            // Configure how to handle exceptions, especially for unauthenticated users.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) ->
                    // If an unauthenticated user tries to access a protected resource, send a 401 error.
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")
                )
            )
            // Define the authorization rules for your API endpoints.
            .authorizeHttpRequests(auth -> auth
                // Allow browsers to make pre-flight OPTIONS requests without authentication.
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                // Allow anyone to access the registration and login endpoints.
                .requestMatchers("/api/auth/**").permitAll()
                // Require authentication for ALL other requests.
                .anyRequest().authenticated()
            )
            // Configure how Spring Security handles the login process.
            .formLogin(formLogin -> formLogin
                .loginProcessingUrl("/api/auth/login") // The URL Spring Security will listen on.
                .successHandler((request, response, authentication) -> {
                    // On success, just send a 200 OK. The frontend will handle navigation.
                    response.setStatus(HttpServletResponse.SC_OK);
                })
                .failureHandler((request, response, exception) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid username or password");
                })
            )
            // Configure how Spring Security handles the logout process.
            .logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler((request, response, authentication) ->
                    response.setStatus(HttpServletResponse.SC_OK)
                )
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
            );

        return http.build();
    }
    
    /**
     * This bean provides the global CORS configuration, making it flexible for both
     * local development and the deployed environment on Render.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
        // Reads the frontend URL from an environment variable, with a fallback for local dev.
        @Value("${frontend.origin.url:http://localhost:5173}") String frontendOriginUrl) {
        
        CorsConfiguration configuration = new CorsConfiguration();
        // Allow requests from both your local machine and your deployed frontend.
        configuration.setAllowedOrigins(List.of("http://localhost:5173", frontendOriginUrl));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setAllowCredentials(true); // This is crucial for session cookies.
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}