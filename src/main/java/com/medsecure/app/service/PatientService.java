package com.medsecure.app.service;

import com.medsecure.app.model.Patient;
import com.medsecure.app.repository.PatientRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class PatientService {

    private static final Logger logger = LoggerFactory.getLogger(PatientService.class);

    private final PatientRepository patientRepository;

    public PatientService(PatientRepository patientRepository) {
        this.patientRepository = patientRepository;
    }

    public List<Patient> getAllPatients() {
        logger.info("Retrieving all patients from database");
        return patientRepository.findAll();
    }

    public Optional<Patient> getPatientById(Long id) {
        logger.info("Looking up patient with ID: {}", id);
        return patientRepository.findById(id);
    }

    /**
     * VULNERABILITY: Sensitive Data Written to Logs
     * Patient SSN (Social Security Number) is logged in plaintext.
     * This sensitive PII should never appear in application logs as it
     * could be exposed through log aggregation systems or log files.
     */
    public Patient createPatient(Patient patient) {
        logger.info("Creating new patient record: {} {}, SSN: {}, DOB: {}",
                patient.getFirstName(),
                patient.getLastName(),
                patient.getSsn(),
                patient.getDateOfBirth());

        Patient saved = patientRepository.save(patient);

        logger.info("Patient created successfully with ID: {}, SSN: {}",
                saved.getId(), saved.getSsn());

        return saved;
    }

    public Optional<Patient> getPatientBySsn(String ssn) {
        logger.info("Searching for patient with SSN: {}", ssn);
        return patientRepository.findBySsn(ssn);
    }

    public List<Patient> getPatientsByDiagnosis(String diagnosis) {
        logger.info("Searching patients by diagnosis: {}", diagnosis);
        return patientRepository.findByDiagnosisContainingIgnoreCase(diagnosis);
    }

    public void deletePatient(Long id) {
        Optional<Patient> patient = patientRepository.findById(id);
        if (patient.isPresent()) {
            logger.info("Deleting patient: {} {}, SSN: {}",
                    patient.get().getFirstName(),
                    patient.get().getLastName(),
                    patient.get().getSsn());
            patientRepository.deleteById(id);
        }
    }
}
