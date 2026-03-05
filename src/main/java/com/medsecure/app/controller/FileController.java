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
    private static final Path REPORTS_BASE_PATH = Paths.get(REPORTS_BASE_DIR).normalize().toAbsolutePath(); // Security: Create normalized base path

    /**
     * VULNERABILITY FIXED: Path Traversal
     * The 'filename' parameter is now sanitized to prevent directory traversal attacks.
     * Only allows access to files within the designated reports directory.
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) throws IOException {
        // Security: Sanitize filename and prevent path traversal
        Path requestedPath = REPORTS_BASE_PATH.resolve(filename).normalize();
        
        // Security: Ensure the resolved path is still within the base directory
        if (!requestedPath.startsWith(REPORTS_BASE_PATH)) {
            return ResponseEntity.badRequest().build();
        }
        
        File file = requestedPath.toFile(); // Security: Use sanitized path

        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        String contentType = Files.probeContentType(requestedPath); // Security: Use sanitized path
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