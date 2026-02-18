package com.example.securityscanner.controller;

import com.example.securityscanner.dto.ScanRequest;
import com.example.securityscanner.dto.ScanResultDto;
import com.example.securityscanner.model.ScanResult;
import com.example.securityscanner.repository.ScanResultRepository;
import com.example.securityscanner.service.ScanResultMapper;
import com.example.securityscanner.service.ZapScannerService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/scan")
@CrossOrigin
public class ScanController {

    private final ZapScannerService zapScannerService;
    private final ScanResultRepository repository;

    public ScanController(ZapScannerService zapScannerService, ScanResultRepository repository) {
        this.zapScannerService = zapScannerService;
        this.repository = repository;
    }

    @PostMapping
    public ResponseEntity<ScanResultDto> scan(@RequestBody ScanRequest request) throws Exception {
        if (request == null || request.getUrl() == null || request.getUrl().isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        ScanResult saved = zapScannerService.scanUrl(request.getUrl());
        return ResponseEntity.ok(ScanResultMapper.toDto(saved));
    }

    @GetMapping
    public ResponseEntity<List<ScanResultDto>> getAll() {
        List<ScanResultDto> list = repository.findAll()
                .stream()
                .map(ScanResultMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(list);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScanResultDto> getById(@PathVariable Long id) {
        return repository.findById(id)
                .map(ScanResultMapper::toDto)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }
}

