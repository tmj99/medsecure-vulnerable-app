package com.medsecure.app.controller;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private static final String REPORTS_BASE_DIR = "/opt/medsecure/reports/";

    /**
     * Downloads a report file with path traversal protection.
     * The filename parameter is validated to prevent directory traversal attacks.
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) throws IOException {
        // Fix: Sanitize filename to prevent path traversal attacks
        String sanitizedFilename = sanitizeFilename(filename);
        if (sanitizedFilename == null) {
            return ResponseEntity.badRequest().build();
        }
        
        // Fix: Use Path.resolve() to safely construct the file path
        Path basePath = Paths.get(REPORTS_BASE_DIR).normalize();
        Path filePath = basePath.resolve(sanitizedFilename).normalize();
        
        // Fix: Verify the resolved path is still within the base directory
        if (!filePath.startsWith(basePath)) {
            return ResponseEntity.badRequest().build();
        }
        
        File file = filePath.toFile();

        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(file.toPath());
        if (contentType == null) {
            contentType = "application/octet-stream";
        }

        FileSystemResource resource = new FileSystemResource(file);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getName() + "\"")
                .body(resource);
    }

    @GetMapping("/list")
    public ResponseEntity<String[]> listReports() {
        File reportsDir = new File(REPORTS_BASE_DIR);
        if (!reportsDir.exists() || !reportsDir.isDirectory()) {
            return ResponseEntity.ok(new String[]{});
        }
        return ResponseEntity.ok(reportsDir.list());
    }
    
    /**
     * Sanitizes filename to prevent path traversal attacks
     * @param filename the input filename
     * @return sanitized filename or null if invalid
     */
    private String sanitizeFilename(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return null;
        }
        
        // Remove path traversal sequences and invalid characters
        String sanitized = filename.replaceAll("[.]{2,}", "")  // Remove .. sequences
                                  .replaceAll("[/\\\\]", "")      // Remove path separators
                                  .replaceAll("[\\x00-\\x1F\\x7F]", "") // Remove control characters
                                  .trim();
        
        // Reject if empty after sanitization or contains suspicious patterns
        if (sanitized.isEmpty() || sanitized.contains("..")) {
            return null;
        }
        
        return sanitized;
    }
}