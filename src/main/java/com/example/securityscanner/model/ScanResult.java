package com.example.securityscanner.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;

import java.time.OffsetDateTime;

@Entity
@Table(name = "scan_results")
public class ScanResult {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String targetUrl;

    private String ipAddress;

    private String server;

    private String serverVersion;

    private String technologies;

    @Column(length = 512)
    private String openPorts;

    @Column(length = 512)
    private String sqlInjectionSummary;

    @Column(length = 512)
    private String xssSummary;

    @Column(length = 1024)
    private String securityHeaders;

    private String overallRiskLevel;

    @Lob
    private String rawAlertsJson;

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

    public String getRawAlertsJson() {
        return rawAlertsJson;
    }

    public void setRawAlertsJson(String rawAlertsJson) {
        this.rawAlertsJson = rawAlertsJson;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }
}

