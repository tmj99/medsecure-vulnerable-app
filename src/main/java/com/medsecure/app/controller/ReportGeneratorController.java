package com.medsecure.app.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/reports")
public class ReportGeneratorController {

    /**
     * VULNERABILITY: Command Injection (OS Command Injection)
     * The 'reportName' parameter from user input is concatenated directly into
     * an OS command string passed to Runtime.exec(). An attacker can inject
     * arbitrary commands using shell metacharacters (e.g., "; rm -rf /").
     * Fix: Use parameterized commands or validate/sanitize user input against
     * an allowlist of permitted report names.
     */
    @GetMapping("/generate")
    public ResponseEntity<String> generateReport(@RequestParam String reportName) {
        try {
            String command = "cat /opt/medsecure/reports/" + reportName;
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

            String output = new BufferedReader(
                    new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));

            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return ResponseEntity.internalServerError()
                        .body("Report generation failed with exit code: " + exitCode);
            }

            return ResponseEntity.ok(output);
        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error generating report: " + e.getMessage());
        }
    }
}
