package com.ziminpro.twitter.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    @Bean
    public WebClient webClient() {

        return WebClient.builder()
                .filter((request, next) ->
                        ReactiveSecurityContextHolder.getContext()
                                .map(ctx -> ctx.getAuthentication())
                                .flatMap(auth -> {

                                    Object credentials = auth.getCredentials();

                                    if (credentials == null) {
                                        return next.exchange(request);
                                    }

                                    return next.exchange(
                                            ClientRequest.from(request)
                                                    .header(
                                                            HttpHeaders.AUTHORIZATION,
                                                            "Bearer " + credentials
                                                    )
                                                    .build()
                                    );
                                })
                                .switchIfEmpty(next.exchange(request))
                )
                .build();
    }
}
