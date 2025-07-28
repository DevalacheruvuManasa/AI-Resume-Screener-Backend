package com.resumescreener.gemini.config;

import com.resumescreener.gemini.service.MongoUserDetailsService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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

import java.util.Arrays;
import java.util.List;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // MongoUserDetailsService is now used automatically by Spring Security's default AuthenticationManager.
    // We don't need to inject it here.
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * This bean is the most critical part for a successful deployment.
     * It configures the session cookie to work across different subdomains
     * (e.g., your-frontend.onrender.com and your-backend.onrender.com).
     */
    @Bean
    public CookieSerializer cookieSerializer() {
        DefaultCookieSerializer serializer = new DefaultCookieSerializer();
        // The SameSite=None attribute is required for modern browsers to send cookies in a cross-origin context.
        serializer.setSameSite("None"); 
        // The Secure attribute is a requirement for SameSite=None. It ensures cookies are only sent over HTTPS.
        serializer.setUseSecureCookie(true);
        // We remove the domain pattern to let the browser handle domain scoping, which is often more reliable
        // behind the proxies used by platforms like Render.
        return serializer;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Use the global CORS configuration defined in the corsConfigurationSource bean.
            .cors(withDefaults())
            // Disable CSRF protection, which is standard for APIs consumed by JavaScript frontends.
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                // Allow public (unauthenticated) access to all registration and login endpoints.
                .requestMatchers("/api/auth/**").permitAll()
                // Require authentication for ALL other requests.
                .anyRequest().authenticated()
            )
            // Use the standard form login mechanism. It's the most reliable way to create a session cookie.
            .formLogin(formLogin -> formLogin
                .loginProcessingUrl("/api/auth/login") // This is the URL Spring Security listens on for login credentials.
                .successHandler((request, response, authentication) -> {
                    response.setStatus(HttpServletResponse.SC_OK); // Send a simple 200 OK on success.
                })
                .failureHandler((request, response, exception) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid username or password");
                })
            )
            .logout(logout -> logout
                .logoutUrl("/api/auth/logout")
                .logoutSuccessHandler((request, response, authentication) ->
                    response.setStatus(HttpServletResponse.SC_OK)
                )
                .deleteCookies("JSESSIONID")
                .invalidateHttpSession(true)
            )
            // This ensures that if an unauthenticated user tries to access a protected page,
            // they get a 401 error, not an HTML login page redirect.
            .exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, authException) ->
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized")
                )
            );

        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource(
        // Reads the frontend URL from an environment variable, with a fallback for local dev.
        @Value("${frontend.origin.url:http://localhost:5173}") String frontendOriginUrl) {
        
        CorsConfiguration configuration = new CorsConfiguration();
        // We list both our local development server and the live deployed frontend URL.
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:5173", frontendOriginUrl));
        // Allow all standard HTTP methods.
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        // Allow all headers for maximum compatibility. Proxies can sometimes add custom headers.
        configuration.setAllowedHeaders(Arrays.asList("*"));
        // This is CRITICAL. It tells the browser that the frontend is allowed to send credentials (cookies).
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}