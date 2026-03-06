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
import java.nio.file.Path; // Added for secure path validation
import java.nio.file.Paths; // Added for secure path validation

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
        // Fixed: Added secure path validation to prevent path traversal attacks
        Path basePath = Paths.get(REPORTS_BASE_DIR).toRealPath();
        Path requestedPath = basePath.resolve(filename).toRealPath();
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
}
