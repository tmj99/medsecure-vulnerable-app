package com.medsecure.app.repository;

import com.medsecure.app.model.Patient;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PatientRepository extends JpaRepository<Patient, Long> {

    Optional<Patient> findBySsn(String ssn);

    List<Patient> findByLastNameContainingIgnoreCase(String lastName);

    List<Patient> findByDiagnosisContainingIgnoreCase(String diagnosis);
}
