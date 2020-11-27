package com.forsrc.oauth2.client.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {


    @GetMapping(path = "/test")
    public String test(Principal principal) {
        return "test " + principal;
        
                
                
    }
}
