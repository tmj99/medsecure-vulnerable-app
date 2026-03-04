package com.medsecure.app.config;

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

    /**
     * VULNERABILITY: Hardcoded Credentials
     * Admin username and password are hardcoded directly in the source code.
     * These credentials should be externalized to environment variables or a
     * secrets management system.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder.encode("MedSecure_Admin#2024!"))
                .roles("ADMIN")
                .build();

        UserDetails doctor = User.builder()
                .username("dr.smith")
                .password(passwordEncoder.encode("Patient$Access99"))
                .roles("DOCTOR")
                .build();

        UserDetails nurse = User.builder()
                .username("nurse.jones")
                .password(passwordEncoder.encode("NurseStation#42"))
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
            // SECURITY FIX: Enable CSRF protection for healthcare data security
            // Only disable for H2 console in dev environment to allow iframe access
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/h2-console/**")
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
