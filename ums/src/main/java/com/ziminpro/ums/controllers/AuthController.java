package com.ziminpro.ums.controllers;

import com.ziminpro.ums.dtos.AuthRequest;
import com.ziminpro.ums.dtos.AuthResponse;
import com.ziminpro.ums.dtos.Constants;
import com.ziminpro.ums.dtos.RegisterRequest;
import com.ziminpro.ums.services.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody AuthRequest request) {
        try {
            AuthResponse authResponse = authService.login(request);

            Map<String, Object> response = new HashMap<>();
            response.put(Constants.CODE, "200");
            response.put(Constants.MESSAGE, "Login successful");
            response.put(Constants.DATA, authResponse);

            return (ResponseEntity.ok()
                    .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                    .body(response));
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put(Constants.CODE, "401");
            response.put(Constants.MESSAGE, "Authentication failed: " + e.getMessage());
            response.put(Constants.DATA, new HashMap<>());

            return (ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                    .body(response));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(@RequestBody RegisterRequest request) {
        try {
            AuthResponse authResponse = authService.register(request);

            Map<String, Object> response = new HashMap<>();
            response.put(Constants.CODE, "201");
            response.put(Constants.MESSAGE, "Registration successful");
            response.put(Constants.DATA, authResponse);

            return (ResponseEntity.status(HttpStatus.CREATED)
                    .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                    .body(response));
        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put(Constants.CODE, "400");
            response.put(Constants.MESSAGE, "Registration failed: " + e.getMessage());
            response.put(Constants.DATA, new HashMap<>());

            return (ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .header(Constants.CONTENT_TYPE, Constants.APPLICATION_JSON)
                    .body(response));
        }
    }
}
