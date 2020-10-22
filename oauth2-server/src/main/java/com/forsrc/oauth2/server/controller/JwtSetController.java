package com.forsrc.oauth2.server.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;

@RestController
public class JwtSetController {

    @Autowired
    private JWKSet jwkSet;
 
    @GetMapping("/oauth/jwks")
    public Map<String, Object> keys() {
        return this.jwkSet.toJSONObject();
    }
}