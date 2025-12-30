package com.ziminpro.ums.services;

import com.ziminpro.ums.dao.UmsRepository;
import com.ziminpro.ums.dtos.AuthRequest;
import com.ziminpro.ums.dtos.AuthResponse;
import com.ziminpro.ums.dtos.RegisterRequest;
import com.ziminpro.ums.dtos.Roles;
import com.ziminpro.ums.dtos.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

@Service
@Slf4j
public class AuthService {

    private final UmsRepository umsRepository;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UmsRepository umsRepository, JwtService jwtService, AuthenticationManager authenticationManager) {
        this.umsRepository = umsRepository;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    public AuthResponse login(AuthRequest request) {
        log.info("Attempting login for email={}", request.getEmail());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        User user = umsRepository.findUserByEmail(request.getEmail());
        if (user == null) {
            throw new RuntimeException("User not found");
        }

        umsRepository.updateLastVisit(user.getId());

        String token = jwtService.generateToken(
                user.getId(),
                user.getName(),
                user.getEmail()
        );

        log.info("Login successful for email={}", request.getEmail());

        return new AuthResponse(
                token,
                jwtService.getExpirationTime(),
                "Login successful",
                user.getId().toString()
        );
    }

    public AuthResponse register(RegisterRequest request) {
        log.info("Attempting registration for email={}", request.getEmail());

        if (umsRepository.findUserByEmail(request.getEmail()) != null) {
            throw new RuntimeException("User with this email already exists");
        }

        User newUser = new User();
        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(request.getPassword());
        newUser.setRoles(new ArrayList<>());

        Map<String, Roles> availableRoles = umsRepository.findAllRoles();
        for (String roleName : request.getRoles()) {
            Roles role = availableRoles.get(roleName);
            if (role != null) {
                newUser.addRole(role);
            }
        }

        UUID userId = umsRepository.createUser(newUser);
        if (userId == null) {
            throw new RuntimeException("Failed to create user");
        }

        log.info("Registration successful for email={}", request.getEmail());

        String token = jwtService.generateToken(
                userId,
                newUser.getName(),
                newUser.getEmail()
        );

        return new AuthResponse(
                token,
                jwtService.getExpirationTime(),
                "Registration successful",
                userId.toString()
        );
    }
}
