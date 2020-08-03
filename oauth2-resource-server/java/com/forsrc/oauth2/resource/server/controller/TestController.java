package com.forsrc.oauth2.resource.server.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/test")
public class TestController {


    @GetMapping()
    public String test(Principal principal) {
        return "test -> " + principal;
    }
}
