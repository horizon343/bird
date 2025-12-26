package com.ziminpro.twitter.security;

import com.ziminpro.twitter.services.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationWebFilter implements WebFilter {

    private final JwtService jwtService;

    public JwtAuthenticationWebFilter(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String token = authHeader.substring(7);
        if (!jwtService.isTokenValid(token)) {
            log.warn("Invalid JWT token received");
            return chain.filter(exchange);
        }

        String email = jwtService.extractEmail(token);
        if (email == null) {
            return chain.filter(exchange);
        }

        var authentication = new UsernamePasswordAuthenticationToken(email, null, null);
        var context = new SecurityContextImpl(authentication);

        log.debug("Reactive JWT authentication for user '{}'", email);

        return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withSecurityContext(Mono.just(context)));
    }
}
