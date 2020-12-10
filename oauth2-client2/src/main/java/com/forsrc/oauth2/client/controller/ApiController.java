package com.forsrc.oauth2.client.controller;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponentsBuilder;

import reactor.core.publisher.Mono;

@RestController
public class ApiController {

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiController.class);
    @Autowired
    private WebClient webClient;


    @Value("${my.oauth2-rource-server}")
    private String rourceServer;

    @GetMapping(path = "/api/test")
    public Mono<String> test() {

        return webClient.get()
                .uri(UriComponentsBuilder.fromHttpUrl(rourceServer).pathSegment("api/test").build().toUri()).retrieve()
                .bodyToMono(String.class);

    }

    @GetMapping(path = "/api/me")
    public Mono<Map> me(@RegisteredOAuth2AuthorizedClient("my-oauth2") OAuth2AuthorizedClient authorizedClient) {


        return webClient.get()
                .uri(UriComponentsBuilder.fromHttpUrl(rourceServer).pathSegment("api/me").build().toUri())
                .header("Authorization", authorizedClient.getAccessToken().getTokenType().getValue() + " " + authorizedClient.getAccessToken().getTokenValue())
                .retrieve()
                .bodyToMono(Map.class);

    }

}
