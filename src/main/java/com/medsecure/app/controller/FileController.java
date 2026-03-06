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
import java.nio.file.Path; // Added for path validation to prevent path traversal
import java.nio.file.Paths; // Added for path validation to prevent path traversal

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
        // Replaced direct concatenation with path validation to prevent path traversal attacks
        Path basePath = Paths.get(REPORTS_BASE_DIR).toRealPath();
        Path requestedPath = basePath.resolve(filename).toRealPath();
        if (!requestedPath.startsWith(basePath)) {
            return ResponseEntity.badRequest().build();
        }
        File file = requestedPath.toFile();

        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        // Replaced file.toPath() with validated requestedPath to use secure path
        String contentType = Files.probeContentType(requestedPath);
        if (contentType == null) {
            contentType = "application/octet-stream";
        }

        // Replaced file parameter with validated requestedPath to ensure secure file access
        FileSystemResource resource = new FileSystemResource(requestedPath.toFile());

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(contentType))
                // Replaced file.getName() with validated path filename to prevent header manipulation
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + requestedPath.getFileName().toString() + "\"")
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
