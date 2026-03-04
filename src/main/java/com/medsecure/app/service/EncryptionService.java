package com.medsecure.app.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

@Service
public class EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    /**
     * VULNERABILITY: Weak Cryptographic Algorithm (MD5)
     * MD5 is a broken hashing algorithm susceptible to collision attacks.
     * For sensitive healthcare data, a strong algorithm like SHA-256 or
     * bcrypt should be used instead.
     */
    public String hashPatientIdentifier(String identifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashBytes = digest.digest(identifier.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Hashing algorithm not available", e);
            throw new RuntimeException("Failed to hash patient identifier", e);
        }
    }

    /**
     * Generates a checksum for medical record integrity verification.
     * Also uses MD5 — another instance of the weak crypto vulnerability.
     */
    public String generateRecordChecksum(String recordContent) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hashBytes = digest.digest(recordContent.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hashBytes);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Failed to generate record checksum", e);
            throw new RuntimeException("Checksum generation failed", e);
        }
    }
}
