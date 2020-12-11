package com.forsrc.oauth2.server.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserInfoController {


    @GetMapping(path = "/oauth/user_info", produces = MediaType.APPLICATION_JSON_VALUE)
    //@PreAuthorize("isAuthenticated()")
    public ResponseEntity<Principal> user(Principal principal) {
        System.out.println("-> Principal: " + principal);
        return ResponseEntity.ok(principal);
    }
}