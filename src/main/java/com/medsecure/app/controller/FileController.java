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
     * VULNERABILITY: Path Traversal
     * The 'filename' parameter is appended directly to the base directory path
     * without sanitization. An attacker can use "../" sequences to read arbitrary
     * files on the server filesystem.
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) throws IOException {
        // SECURITY FIX: Validate filename to prevent path traversal attacks
        if (filename == null || filename.isEmpty() || 
            filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            return ResponseEntity.badRequest().build();
        }
        
        // SECURITY FIX: Use Paths.resolve() and normalize() to safely construct path
        Path basePath = Paths.get(REPORTS_BASE_DIR).normalize();
        Path filePath = basePath.resolve(filename).normalize();
        
        // SECURITY FIX: Ensure resolved path is still within base directory
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
}
