package com.example.securityscanner.service;

import com.example.securityscanner.dto.ScanResultDto;
import com.example.securityscanner.model.ScanResult;

public class ScanResultMapper {

    private ScanResultMapper() {
    }

    public static ScanResultDto toDto(ScanResult entity) {
        ScanResultDto dto = new ScanResultDto();
        dto.setId(entity.getId());
        dto.setTargetUrl(entity.getTargetUrl());
        dto.setIpAddress(entity.getIpAddress());
        dto.setServer(entity.getServer());
        dto.setServerVersion(entity.getServerVersion());
        dto.setTechnologies(entity.getTechnologies());
        dto.setOpenPorts(entity.getOpenPorts());
        dto.setSqlInjectionSummary(entity.getSqlInjectionSummary());
        dto.setXssSummary(entity.getXssSummary());
        dto.setSecurityHeaders(entity.getSecurityHeaders());
        dto.setOverallRiskLevel(entity.getOverallRiskLevel());
        dto.setCreatedAt(entity.getCreatedAt());
        return dto;
    }
}

