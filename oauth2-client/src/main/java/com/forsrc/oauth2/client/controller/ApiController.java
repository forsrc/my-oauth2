package com.forsrc.oauth2.client.controller;

import java.security.Principal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
public class ApiController {

    @Autowired
    private OAuth2RestTemplate restTemplate;

    @Value("${oauth2-rource-server}")
    private String rourceServer;

    @GetMapping(path = "/api/test")
    public String test(Principal principal) {
        return restTemplate.getForEntity(UriComponentsBuilder.fromHttpUrl(rourceServer).pathSegment("test").build().toUri(),
                String.class)
                .getBody();
                
    }
}
