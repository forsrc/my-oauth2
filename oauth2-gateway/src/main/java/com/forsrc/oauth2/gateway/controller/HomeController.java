package com.forsrc.oauth2.gateway.controller;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
public class HomeController {


    @RequestMapping("/")
    public String test(Principal principal) {
        return "/index";

    }
}
