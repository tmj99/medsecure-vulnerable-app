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
     * Downloads medical reports with path traversal protection.
     * The filename is validated to prevent directory traversal attacks.
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) throws IOException {
        // Sanitize filename to prevent path traversal attacks
        String sanitizedFilename = sanitizeFilename(filename);
        if (sanitizedFilename == null) {
            return ResponseEntity.badRequest().build();
        }
        
        // Resolve the path and ensure it stays within the reports directory
        Path basePath = Paths.get(REPORTS_BASE_DIR).normalize();
        Path filePath = basePath.resolve(sanitizedFilename).normalize();
        
        // Security check: ensure the resolved path is still within the base directory
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
     * Sanitizes the filename to prevent path traversal attacks by removing
     * directory navigation characters and invalid file name characters.
     */
    private String sanitizeFilename(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return null;
        }
        
        // Remove path separators and traversal sequences
        String sanitized = filename.replaceAll("[/\\\\..]", "");
        
        // Remove other potentially dangerous characters
        sanitized = sanitized.replaceAll("[^a-zA-Z0-9._-]", "");
        
        // Ensure the sanitized filename is not empty and has reasonable length
        if (sanitized.trim().isEmpty() || sanitized.length() > 255) {
            return null;
        }
        
        return sanitized;
    }
}