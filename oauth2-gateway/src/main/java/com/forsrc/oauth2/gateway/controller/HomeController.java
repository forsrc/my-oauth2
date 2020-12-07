package com.forsrc.oauth2.gateway.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.security.Principal;


@Controller
public class HomeController {


    @RequestMapping("/")
    public String test(Principal principal) {
        return "/index";

    }
}
