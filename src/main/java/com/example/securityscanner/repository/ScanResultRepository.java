package com.example.securityscanner.repository;

import com.example.securityscanner.model.ScanResult;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanResultRepository extends JpaRepository<ScanResult, Long> {
}

