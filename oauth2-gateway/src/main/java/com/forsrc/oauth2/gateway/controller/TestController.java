package com.forsrc.oauth2.gateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class TestController {


    @GetMapping(path = "/test")
    public String test(Principal principal) {
        return "test " + principal;


    }
}
