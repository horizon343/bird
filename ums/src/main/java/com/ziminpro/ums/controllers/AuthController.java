package com.ziminpro.ums.controllers;

import com.ziminpro.ums.dtos.AuthRequest;
import com.ziminpro.ums.dtos.AuthResponse;
import com.ziminpro.ums.dtos.Constants;
import com.ziminpro.ums.dtos.RegisterRequest;
import com.ziminpro.ums.services.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody AuthRequest request) {
        AuthResponse authResponse = authService.login(request);

        return ResponseEntity.ok()
                .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                .body(Map.of(
                        Constants.CODE, "200",
                        Constants.MESSAGE, "Login successful",
                        Constants.DATA, authResponse
                ));
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        AuthResponse authResponse = authService.register(request);

        return ResponseEntity.status(HttpStatus.CREATED)
                .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                .body(Map.of(
                        Constants.CODE, "201",
                        Constants.MESSAGE, "Registration successful",
                        Constants.DATA, authResponse
                ));
    }
}
