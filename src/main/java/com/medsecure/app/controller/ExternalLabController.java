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
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/lab")
public class ExternalLabController {

    /**
     * VULNERABILITY: Server-Side Request Forgery (SSRF)
     * The 'url' parameter from user input is used directly to open an HTTP
     * connection from the server. An attacker can supply internal network URLs
     * (e.g., http://169.254.169.254/latest/meta-data/ for cloud metadata) or
     * localhost addresses to access internal services not meant to be exposed.
     * Fix: Validate the URL against an allowlist of trusted external domains
     * and block private/internal IP ranges.
     */
    @GetMapping("/results")
    public ResponseEntity<String> fetchLabResults(@RequestParam String url) {
        try {
            URL labUrl = new URL(url);
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
