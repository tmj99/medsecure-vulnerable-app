package com.medsecure.app.controller;

import com.medsecure.app.model.Patient;
import com.medsecure.app.service.PatientService;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import org.springframework.http.MediaType;

@RestController
@RequestMapping("/api/patients")
public class PatientController {

    private final PatientService patientService;

    @PersistenceContext
    private EntityManager entityManager;

    public PatientController(PatientService patientService) {
        this.patientService = patientService;
    }

    @GetMapping
    public ResponseEntity<List<Patient>> getAllPatients() {
        return ResponseEntity.ok(patientService.getAllPatients());
    }

    @GetMapping("/{id}")
    public ResponseEntity<Patient> getPatientById(@PathVariable Long id) {
        return patientService.getPatientById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * VULNERABILITY: SQL Injection
     * User-supplied 'name' parameter is concatenated directly into a native SQL query
     * without parameterization, allowing an attacker to inject arbitrary SQL.
     */
    @SuppressWarnings("unchecked")
    @GetMapping("/search")
    public ResponseEntity<List<Patient>> searchPatients(@RequestParam String name) {
        String sql = "SELECT * FROM patients WHERE first_name LIKE '%" + name + "%' OR last_name LIKE '%" + name + "%'";
        Query query = entityManager.createNativeQuery(sql, Patient.class);
        List<Patient> results = query.getResultList();
        return ResponseEntity.ok(results);
    }

    @PostMapping
    public ResponseEntity<Patient> createPatient(@RequestBody Patient patient) {
        Patient saved = patientService.createPatient(patient);
        return ResponseEntity.ok(saved);
    }

    @GetMapping("/by-diagnosis")
    public ResponseEntity<List<Patient>> getByDiagnosis(@RequestParam String diagnosis) {
        return ResponseEntity.ok(patientService.getPatientsByDiagnosis(diagnosis));
    }

    /**
     * VULNERABILITY: Cross-Site Scripting (XSS)
     * The 'query' parameter from user input is embedded directly into an HTML
     * response without any output encoding or sanitization. An attacker can
     * inject malicious JavaScript (e.g., <script>alert('xss')</script>) that
     * will execute in the victim's browser.
     * Fix: HTML-encode all user-supplied data before including it in HTML output,
     * or use a templating engine that auto-escapes by default.
     */
    @GetMapping(value = "/search-page", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> searchPatientsPage(@RequestParam(required = false) String query) {
        String html = "<html><body><h1>Patient Search</h1>"
                + "<form action='/api/patients/search-page' method='get'>"
                + "<input name='query' value='" + (query != null ? query : "") + "'/>"
                + "<button type='submit'>Search</button>"
                + "</form>";

        if (query != null && !query.isEmpty()) {
            html += "<p>Search results for: " + query + "</p>";
        }

        html += "</body></html>";
        return ResponseEntity.ok(html);
    }
}
