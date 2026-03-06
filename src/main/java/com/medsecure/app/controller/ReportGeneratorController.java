package com.medsecure.app.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Set;

@RestController
@RequestMapping("/api/reports")
public class ReportGeneratorController {

    private static final Logger logger = LoggerFactory.getLogger(ReportGeneratorController.class);
    
    // Allowlist of permitted report names to prevent command injection
    private static final Set<String> ALLOWED_REPORTS = Set.of(
        "patient-summary.txt",
        "medication-list.txt",
        "lab-results.txt",
        "discharge-summary.txt"
    );
    
    private static final String REPORTS_BASE_PATH = "/opt/medsecure/reports/";

    /**
     * FIXED: Command Injection vulnerability remediated by replacing shell command execution
     * with secure direct file I/O operations and input validation.
     */
    @GetMapping("/generate")
    public ResponseEntity<String> generateReport(@RequestParam String reportName) {
        try {
            // Input validation: Check if reportName is in allowlist to prevent command injection
            if (!ALLOWED_REPORTS.contains(reportName)) {
                logger.warn("Attempt to access unauthorized report: {}", reportName);
                return ResponseEntity.badRequest().body("Invalid report name");
            }
            
            // Secure file reading using direct file I/O instead of shell commands
            Path reportPath = Paths.get(REPORTS_BASE_PATH, reportName).normalize();
            
            // Path traversal protection: Ensure the resolved path is within allowed directory
            if (!reportPath.startsWith(Paths.get(REPORTS_BASE_PATH).normalize())) {
                logger.warn("Path traversal attempt detected for report: {}", reportName);
                return ResponseEntity.badRequest().body("Invalid report path");
            }
            
            // Check if file exists
            if (!Files.exists(reportPath)) {
                return ResponseEntity.notFound().build();
            }
            
            // Read file content directly without shell command execution
            String content = Files.readString(reportPath);
            return ResponseEntity.ok(content);
            
        } catch (Exception e) {
            // FIXED: Information disclosure vulnerability - log actual exception server-side but return generic message
            logger.error("Report generation error for report: {}", reportName, e);
            return ResponseEntity.internalServerError().body("Report generation failed");
        }
    }
}
