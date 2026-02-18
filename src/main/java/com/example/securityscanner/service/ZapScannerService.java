package com.example.securityscanner.service;

import com.example.securityscanner.model.ScanResult;
import com.example.securityscanner.repository.ScanResultRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Service
public class ZapScannerService {

    private final RestTemplate restTemplate;
    private final ScanResultRepository repository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${zap.api.baseUrl}")
    private String zapBaseUrl;

    @Value("${zap.api.key:}")
    private String zapApiKey;

    @Value("${zap.scan.pollIntervalMs:5000}")
    private long pollIntervalMs;

    @Value("${zap.scan.timeoutMs:600000}")
    private long timeoutMs;

    public ZapScannerService(RestTemplate restTemplate, ScanResultRepository repository) {
        this.restTemplate = restTemplate;
        this.repository = repository;
    }

    public ScanResult scanUrl(String url) throws Exception {
        String normalizedUrl = normalizeUrl(url);
        URI uri = URI.create(normalizedUrl);

        ScanResult result = new ScanResult();
        result.setTargetUrl(normalizedUrl);
        result.setCreatedAt(OffsetDateTime.now());

        // Resolve IP
        try {
            InetAddress address = InetAddress.getByName(uri.getHost());
            result.setIpAddress(address.getHostAddress());
        } catch (Exception ex) {
            result.setIpAddress("Unknown");
        }

        // Fetch headers to get server info and security headers
        HttpHeaders headers = fetchHeaders(normalizedUrl);
        extractServerAndTechnology(headers, result);
        extractSecurityHeaders(headers, result);

        // Basic port scan on common ports
        String openPorts = scanCommonPorts(uri.getHost());
        result.setOpenPorts(openPorts);

        // Run ZAP active scan and collect alerts
        JsonNode alerts = runZapScanAndGetAlerts(normalizedUrl);
        if (alerts != null) {
            analyzeAlerts(alerts, result);
            result.setRawAlertsJson(alerts.toString());
        }

        return repository.save(result);
    }

    private String normalizeUrl(String url) {
        String trimmed = url.trim();
        if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
            trimmed = "http://" + trimmed;
        }
        return trimmed;
    }

    private HttpHeaders fetchHeaders(String url) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            return response.getHeaders();
        } catch (Exception ex) {
            return new HttpHeaders();
        }
    }

    private void extractServerAndTechnology(HttpHeaders headers, ScanResult result) {
        String serverHeader = headers.getFirst("Server");
        String xPoweredBy = headers.getFirst("X-Powered-By");

        if (serverHeader != null) {
            result.setServer(serverHeader);
            String server = serverHeader;
            String version = null;

            int slashIndex = serverHeader.indexOf('/');
            if (slashIndex > 0 && slashIndex < serverHeader.length() - 1) {
                server = serverHeader.substring(0, slashIndex);
                version = serverHeader.substring(slashIndex + 1);
            }
            result.setServer(server);
            result.setServerVersion(version);
        }

        List<String> tech = new ArrayList<>();
        if (StringUtils.hasText(serverHeader)) {
            tech.add("Server: " + serverHeader);
        }
        if (StringUtils.hasText(xPoweredBy)) {
            tech.add("X-Powered-By: " + xPoweredBy);
        }
        if (!tech.isEmpty()) {
            result.setTechnologies(String.join(", ", tech));
        }
    }

    private void extractSecurityHeaders(HttpHeaders headers, ScanResult result) {
        List<String> interesting = Arrays.asList(
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy"
        );

        List<String> found = new ArrayList<>();
        List<String> foundNames = new ArrayList<>();
        List<String> missing = new ArrayList<>();
        
        for (String name : interesting) {
            String value = headers.getFirst(name);
            if (value != null) {
                found.add(name + ": " + value);
                foundNames.add(name);
            } else {
                missing.add(name);
            }
        }

        List<String> parts = new ArrayList<>();
        if (!foundNames.isEmpty()) {
            parts.add("Found: " + String.join(", ", foundNames));
        }
        if (!missing.isEmpty()) {
            parts.add("Missing: " + String.join(", ", missing));
        }
        
        if (parts.isEmpty()) {
            result.setSecurityHeaders("No common security headers detected");
        } else {
            result.setSecurityHeaders(String.join(" | ", parts));
        }
    }

    private String scanCommonPorts(String host) {
        int[] ports = {
                80, 443, 8080, 8081, 8089, 8443,
                21, 22, 25, 110,
                1433, 1521, 3306, 5432, 6379, 27017
        };
        List<Integer> open = new ArrayList<>();
        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(host, port), 200);
                open.add(port);
            } catch (Exception ignored) {
                // closed or filtered
            }
        }
        if (open.isEmpty()) {
            return "No common ports detected as open";
        }
        return open.toString();
    }

    private JsonNode runZapScanAndGetAlerts(String url) {
        try {
            String encodedUrl = URLEncoder.encode(url, StandardCharsets.UTF_8);
            String apiKeyParam = StringUtils.hasText(zapApiKey) ? "&apikey=" + zapApiKey : "";

            // Start active scan
            String startScanUrl = zapBaseUrl + "/JSON/ascan/action/scan/?url=" + encodedUrl +
                    "&recurse=true&inScopeOnly=false" + apiKeyParam;
            String startResponse = restTemplate.getForObject(startScanUrl, String.class);
            JsonNode startJson = objectMapper.readTree(startResponse);
            String scanId = startJson.path("scan").asText(null);
            if (scanId == null) {
                return null;
            }

            // Poll status until complete or timeout
            long startTime = System.currentTimeMillis();
            while (true) {
                String statusUrl = zapBaseUrl + "/JSON/ascan/view/status/?scanId=" + scanId + apiKeyParam;
                String statusResponse = restTemplate.getForObject(statusUrl, String.class);
                JsonNode statusJson = objectMapper.readTree(statusResponse);
                String status = statusJson.path("status").asText("0");
                if ("100".equals(status)) {
                    break;
                }
                if (System.currentTimeMillis() - startTime > timeoutMs) {
                    break;
                }
                Thread.sleep(pollIntervalMs);
            }

            // Get alerts for the base URL
            String alertsUrl = zapBaseUrl + "/JSON/core/view/alerts/?baseurl=" + encodedUrl +
                    "&start=0&count=9999" + apiKeyParam;
            String alertsResponse = restTemplate.getForObject(alertsUrl, String.class);
            JsonNode alertsJson = objectMapper.readTree(alertsResponse);
            return alertsJson.path("alerts");
        } catch (Exception ex) {
            return null;
        }
    }

    private void analyzeAlerts(JsonNode alerts, ScanResult result) {
        if (alerts == null || !alerts.isArray()) {
            return;
        }

        String highestRisk = "Informational";
        int sqlCount = 0;
        int xssCount = 0;

        for (JsonNode alert : alerts) {
            String risk = alert.path("risk").asText(alert.path("riskString").asText("Informational"));
            highestRisk = maxRisk(highestRisk, risk);

            String name = alert.path("name").asText("").toLowerCase();
            if (name.contains("sql injection")) {
                sqlCount++;
            }
            if (name.contains("cross site scripting") || name.contains("xss")) {
                xssCount++;
            }
        }

        result.setOverallRiskLevel(highestRisk);

        if (sqlCount > 0) {
            result.setSqlInjectionSummary("Found " + sqlCount + " potential SQL Injection issues");
        } else {
            result.setSqlInjectionSummary("No SQL Injection issues detected by ZAP");
        }

        if (xssCount > 0) {
            result.setXssSummary("Found " + xssCount + " potential XSS issues");
        } else {
            result.setXssSummary("No XSS issues detected by ZAP");
        }
    }

    private String maxRisk(String current, String candidate) {
        int currentRank = riskRank(current);
        int candidateRank = riskRank(candidate);
        return candidateRank > currentRank ? normalizeRisk(candidate) : normalizeRisk(current);
    }

    private int riskRank(String risk) {
        String r = normalizeRisk(risk);
        return switch (r) {
            case "High" -> 4;
            case "Medium" -> 3;
            case "Low" -> 2;
            case "Informational" -> 1;
            default -> 0;
        };
    }

    private String normalizeRisk(String risk) {
        if (risk == null) {
            return "Informational";
        }
        String r = risk.toLowerCase();
        if (r.contains("high")) return "High";
        if (r.contains("medium")) return "Medium";
        if (r.contains("low")) return "Low";
        if (r.contains("inform")) return "Informational";
        return "Informational";
    }
}

