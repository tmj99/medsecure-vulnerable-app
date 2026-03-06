package com.medsecure.app.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    // Fixed: Externalize credentials to environment variables to avoid hardcoded secrets
    @Value("${app.admin.username:admin}")
    private String adminUsername;
    
    @Value("${app.admin.password}")
    private String adminPassword;
    
    @Value("${app.doctor.username:dr.smith}")
    private String doctorUsername;
    
    @Value("${app.doctor.password}")
    private String doctorPassword;
    
    @Value("${app.nurse.username:nurse.jones}")
    private String nurseUsername;
    
    @Value("${app.nurse.password}")
    private String nursePassword;

    /**
     * VULNERABILITY: Hardcoded Credentials
     * Admin username and password are hardcoded directly in the source code.
     * These credentials should be externalized to environment variables or a
     * secrets management system.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails admin = User.builder()
                .username(adminUsername)
                .password(passwordEncoder.encode(adminPassword))
                .roles("ADMIN")
                .build();

        UserDetails doctor = User.builder()
                .username(doctorUsername)
                .password(passwordEncoder.encode(doctorPassword))
                .roles("DOCTOR")
                .build();

        UserDetails nurse = User.builder()
                .username(nurseUsername)
                .password(passwordEncoder.encode(nursePassword))
                .roles("NURSE")
                .build();

        return new InMemoryUserDetailsManager(admin, doctor, nurse);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Fixed: Enable CSRF protection by default for healthcare app security
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**") // Only disable CSRF for H2 console in development
            )
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/patients/**").hasAnyRole("ADMIN", "DOCTOR")
                .requestMatchers("/api/files/**").hasRole("ADMIN")
                .requestMatchers("/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> {})
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        return http.build();
    }
}