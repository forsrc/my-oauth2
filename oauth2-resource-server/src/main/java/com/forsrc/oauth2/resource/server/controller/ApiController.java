package com.forsrc.oauth2.resource.server.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api")
public class ApiController {


    @GetMapping("/test")
    public String test(Principal principal) {
    	System.out.println("test -> " + principal);
        return "test -> " + principal.getName();
    }
    
    @GetMapping("/me")
    public Principal me(Principal principal) {
    	System.out.println("test -> " + principal);
        return principal;
    }
}
