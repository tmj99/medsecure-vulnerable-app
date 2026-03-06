package com.medsecure.app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/lab")
public class ExternalLabController {

    private static final Logger logger = LoggerFactory.getLogger(ExternalLabController.class);
    
    // Allowlist of trusted external lab domains
    private static final List<String> TRUSTED_DOMAINS = Arrays.asList(
        "labcorp.com",
        "questdiagnostics.com",
        "trustedlabs.example.com"
    );

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
            // SSRF fix: Validate URL before use - check against allowlist and block private IPs
            URL validatedUrl = validateUrl(url);
            if (validatedUrl == null) {
                return ResponseEntity.badRequest().body("Invalid or untrusted URL");
            }
            
            HttpURLConnection connection = (HttpURLConnection) validatedUrl.openConnection();
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
            // Error message exposure fix: Log detailed error internally but return generic message
            logger.error("Failed to fetch lab results from URL: {}", url, e);
            return ResponseEntity.internalServerError()
                    .body("Failed to fetch lab results");
        }
    }
    
    /**
     * Validates URL against trusted domains and blocks private/internal IP ranges
     * @param urlString The URL string to validate
     * @return Validated URL object or null if invalid
     */
    private URL validateUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            String host = url.getHost();
            
            // Check if domain is in trusted allowlist
            boolean isTrusted = TRUSTED_DOMAINS.stream()
                    .anyMatch(domain -> host.endsWith(domain));
            
            if (!isTrusted) {
                return null;
            }
            
            // Block private and internal IP ranges
            InetAddress address = InetAddress.getByName(host);
            if (address.isLoopbackAddress() || 
                address.isLinkLocalAddress() || 
                address.isSiteLocalAddress() ||
                address.isAnyLocalAddress()) {
                return null;
            }
            
            // Block cloud metadata endpoints and other common internal addresses
            String hostLower = host.toLowerCase();
            if (hostLower.equals("169.254.169.254") || 
                hostLower.equals("metadata.google.internal") ||
                hostLower.startsWith("10.") ||
                hostLower.startsWith("192.168.") ||
                (hostLower.startsWith("172.") && isInRange172(hostLower))) {
                return null;
            }
            
            return url;
        } catch (Exception e) {
            logger.warn("URL validation failed for: {}", urlString, e);
            return null;
        }
    }
    
    /**
     * Check if IP is in 172.16.0.0/12 private range
     */
    private boolean isInRange172(String host) {
        try {
            String[] parts = host.split("\\.");
            if (parts.length >= 2) {
                int secondOctet = Integer.parseInt(parts[1]);
                return secondOctet >= 16 && secondOctet <= 31;
            }
        } catch (NumberFormatException e) {
            // Not a valid IP format
        }
        return false;
    }
}