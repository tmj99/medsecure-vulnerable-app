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
     * Only allows access to files within the designated reports directory.
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) throws IOException {
        // Sanitize filename to prevent path traversal attacks
        String sanitizedFilename = sanitizeFilename(filename);
        if (sanitizedFilename == null) {
            return ResponseEntity.badRequest().build();
        }
        
        // Resolve the file path and ensure it's within the allowed directory
        Path basePath = Paths.get(REPORTS_BASE_DIR).toRealPath();
        Path requestedPath = basePath.resolve(sanitizedFilename).normalize();
        
        // Verify the resolved path is still within the base directory
        if (!requestedPath.startsWith(basePath)) {
            return ResponseEntity.badRequest().build();
        }
        
        File file = requestedPath.toFile();

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
     * Sanitizes filename input to prevent path traversal attacks.
     * Removes dangerous characters and path traversal sequences.
     */
    private String sanitizeFilename(String filename) {
        if (filename == null || filename.trim().isEmpty()) {
            return null;
        }
        
        // Remove any path separators and traversal sequences
        String sanitized = filename.replaceAll("[\\\\/]", "")
                                  .replaceAll("\\.\\.", "")
                                  .replaceAll("[\\x00-\\x1f]", ""); // Remove control characters
        
        // Ensure we still have a valid filename after sanitization
        if (sanitized.trim().isEmpty()) {
            return null;
        }
        
        return sanitized;
    }
}