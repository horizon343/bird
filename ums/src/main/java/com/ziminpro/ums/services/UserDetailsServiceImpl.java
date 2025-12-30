package com.ziminpro.ums.services;

import com.ziminpro.ums.dao.UmsRepository;
import com.ziminpro.ums.dtos.Roles;
import com.ziminpro.ums.dtos.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UmsRepository umsRepository;

    public UserDetailsServiceImpl(UmsRepository umsRepository) {
        this.umsRepository = umsRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {

        log.debug("Loading user by email={}", email);

        User user = umsRepository.findUserByEmail(email);

        if (user == null) {
            throw new UsernameNotFoundException("User not found with email=" + email);
        }

        List<GrantedAuthority> authorities = user.getRoles()
                .stream()
                .map(Roles::getRole)
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .authorities(authorities)
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .disabled(false)
                .build();
    }
}
