package com.medsecure.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/reports")
public class ReportGeneratorController {

    private static final Logger logger = LoggerFactory.getLogger(ReportGeneratorController.class);
    
    // Map allowed report names to hardcoded absolute file paths
    private static final Map<String, String> REPORT_PATH_MAPPING = Map.of(
        "patient-summary.txt", "/opt/medsecure/reports/patient-summary.txt",
        "medication-list.txt", "/opt/medsecure/reports/medication-list.txt",
        "lab-results.txt", "/opt/medsecure/reports/lab-results.txt",
        "discharge-summary.txt", "/opt/medsecure/reports/discharge-summary.txt"
    );

    /**
     * FIXED: Command Injection vulnerability
     * Now uses hardcoded path mapping instead of constructing paths from user input
     */
    @GetMapping("/generate")
    public ResponseEntity<String> generateReport(@RequestParam String reportName) {
        try {
            // Get the hardcoded path without using user input in path construction
            String hardcodedPath = REPORT_PATH_MAPPING.get(reportName);
            if (hardcodedPath == null) {
                logger.warn("Attempt to access unauthorized report: {}", reportName);
                return ResponseEntity.badRequest().body("Invalid report name");
            }

            Path reportPath = Paths.get(hardcodedPath); // Fixed: Now using hardcoded path instead of user input
            
            // Verify the file exists and is readable
            if (!Files.exists(reportPath) || !Files.isReadable(reportPath)) {
                logger.error("Report file not found or not readable: {}", hardcodedPath);
                return ResponseEntity.notFound().build();
            }

            // Read the file content directly instead of using system commands
            String content = Files.readString(reportPath, StandardCharsets.UTF_8);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            logger.error("Error reading report file", e);
            return ResponseEntity.internalServerError()
                    .body("Error generating report: " + e.getMessage());
        }
    }
}