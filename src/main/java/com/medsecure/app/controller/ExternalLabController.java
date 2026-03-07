package com.medsecure.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/lab")
public class ExternalLabController {

    // Pre-configured trusted lab endpoints mapped by lab ID
    // Changed from TRUSTED_DOMAINS list to LAB_ENDPOINTS map to eliminate user control over URLs
    private static final Map<String, String> LAB_ENDPOINTS = Map.of(
        "labcorp", "https://api.labcorp.com/results",
        "quest", "https://api.questdiagnostics.com/results",
        "trusted-lab", "https://api.trustedlabs.example.com/results"
    );

    /**
     * VULNERABILITY FIXED: Server-Side Request Forgery (SSRF)
     * Previously the 'url' parameter from user input was used directly to open an HTTP
     * connection. Now uses lab ID lookup to prevent user control over target URLs.
     * Fix: Changed to use labId parameter that maps to pre-configured trusted URLs,
     * eliminating any user influence over the actual URL used for connections.
     */
    @GetMapping("/results")
    // Changed parameter from String url to String labId to eliminate user control over URLs
    public ResponseEntity<String> fetchLabResults(@RequestParam String labId) {
        try {
            // Use ID-based lookup instead of user-provided URL to prevent SSRF
            String trustedUrl = LAB_ENDPOINTS.get(labId);
            if (trustedUrl == null) {
                return ResponseEntity.badRequest().body("Invalid lab ID");
            }
            
            URL labUrl = new URL(trustedUrl);
            HttpURLConnection connection = (HttpURLConnection) labUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);

            int responseCode = connection.getResponseCode();
            if (responseCode != 200) {
                return ResponseEntity.status(responseCode)
                        .body("Lab service returned status: " + responseCode);
            }

            String responseBody = new BufferedReader(
                    new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));

            connection.disconnect();
            return ResponseEntity.ok(responseBody);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Failed to fetch lab results: " + e.getMessage());
        }
    }
}
