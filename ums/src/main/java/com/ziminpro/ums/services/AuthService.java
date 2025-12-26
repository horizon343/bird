package com.ziminpro.ums.services;

import com.ziminpro.ums.dao.UmsRepository;
import com.ziminpro.ums.dtos.AuthRequest;
import com.ziminpro.ums.dtos.AuthResponse;
import com.ziminpro.ums.dtos.RegisterRequest;
import com.ziminpro.ums.dtos.Roles;
import com.ziminpro.ums.dtos.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
public class AuthService {

    @Autowired
    private UmsRepository umsRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    public AuthResponse login(AuthRequest request) throws AuthenticationException {
        log.info("Attempting login for email: {}", request.getEmail());

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getEmail(),
                            request.getPassword()
                    )
            );

            Map<UUID, User> allUsers = umsRepository.findAllUsers();
            User user = allUsers.values().stream()
                    .filter(u -> u.getEmail().equals(request.getEmail()))
                    .findFirst()
                    .orElseThrow(() -> new RuntimeException("User not found"));

            String token = jwtService.generateToken(user.getId(), user.getName(), user.getEmail());

            log.info("Login successful for email: {}", request.getEmail());

            return new AuthResponse(
                    token,
                    jwtService.getExpirationTime(),
                    "Login successful",
                    user.getId().toString()
            );
        } catch (AuthenticationException e) {
            log.error("Login failed for email: {}", request.getEmail());
            throw new RuntimeException("Invalid email or password", e);
        }
    }

    public AuthResponse register(RegisterRequest request) {
        log.info("Attempting registration for email: {}", request.getEmail());

        Map<UUID, User> allUsers = umsRepository.findAllUsers();
        boolean userExists = allUsers.values().stream()
                .anyMatch(u -> u.getEmail().equals(request.getEmail()));

        if (userExists) {
            throw new RuntimeException("User with this email already exists");
        }

        User newUser = new User();
        newUser.setName(request.getName());
        newUser.setEmail(request.getEmail());
        newUser.setPassword(request.getPassword()); // passwordEncoder.encode(request.getPassword())
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

        log.info("Registration successful for email: {}", request.getEmail());

        String token = jwtService.generateToken(userId, request.getName(), request.getEmail());

        return new AuthResponse(
                token,
                jwtService.getExpirationTime(),
                "Registration successful",
                userId.toString()
        );
    }
}
