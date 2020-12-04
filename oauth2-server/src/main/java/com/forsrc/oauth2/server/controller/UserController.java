package com.forsrc.oauth2.server.controller;

import java.security.Principal;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {


    @GetMapping(path = "/me", produces = MediaType.APPLICATION_JSON_VALUE)
    //@PreAuthorize("isAuthenticated()")
    public ResponseEntity<Principal> user(Principal principal) {
        System.out.println("-> Principal: " + principal);
        return ResponseEntity.ok(principal);
    }

    @GetMapping("/test")
    public String test() {
        System.out.println("-> test");
        return "test";
    }
}