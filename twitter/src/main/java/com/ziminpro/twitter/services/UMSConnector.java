package com.ziminpro.twitter.services;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

@Service
public class UMSConnector {

    private final WebClient webClient;

    @Value("${ums.host}")
    private String host;

    @Value("${ums.port}")
    private String port;

    public UMSConnector(WebClient webClient) {
        this.webClient = webClient;
    }

    public Mono<Object> retrieveUmsData(String uri) {
        return webClient.get()
                .uri(host + ":" + port + uri)
                .retrieve()
                .bodyToMono(Object.class);
    }
}
