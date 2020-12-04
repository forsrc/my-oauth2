package com.forsrc.oauth2.resource.server.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {


    @GetMapping("/test")
    public String test(Principal principal) {
        System.out.println("test -> " + principal);
        return "test -> " + principal;
    }
}
