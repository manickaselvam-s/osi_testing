package com.example.securityscanner.dto;

import java.time.OffsetDateTime;

public class ScanResultDto {

    private Long id;
    private String targetUrl;
    private String ipAddress;
    private String server;
    private String serverVersion;
    private String technologies;
    private String openPorts;
    private String sqlInjectionSummary;
    private String xssSummary;
    private String securityHeaders;
    private String overallRiskLevel;
    private OffsetDateTime createdAt;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getServer() {
        return server;
    }

    public void setServer(String server) {
        this.server = server;
    }

    public String getServerVersion() {
        return serverVersion;
    }

    public void setServerVersion(String serverVersion) {
        this.serverVersion = serverVersion;
    }

    public String getTechnologies() {
        return technologies;
    }

    public void setTechnologies(String technologies) {
        this.technologies = technologies;
    }

    public String getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(String openPorts) {
        this.openPorts = openPorts;
    }

    public String getSqlInjectionSummary() {
        return sqlInjectionSummary;
    }

    public void setSqlInjectionSummary(String sqlInjectionSummary) {
        this.sqlInjectionSummary = sqlInjectionSummary;
    }

    public String getXssSummary() {
        return xssSummary;
    }

    public void setXssSummary(String xssSummary) {
        this.xssSummary = xssSummary;
    }

    public String getSecurityHeaders() {
        return securityHeaders;
    }

    public void setSecurityHeaders(String securityHeaders) {
        this.securityHeaders = securityHeaders;
    }

    public String getOverallRiskLevel() {
        return overallRiskLevel;
    }

    public void setOverallRiskLevel(String overallRiskLevel) {
        this.overallRiskLevel = overallRiskLevel;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}

