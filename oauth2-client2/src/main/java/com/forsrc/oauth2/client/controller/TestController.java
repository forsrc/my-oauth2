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
    
    public static void main(String[] args) {
		String s = "http://my-oauth2:22000/oauth2-client/test";
		System.out.println(s.substring(s.indexOf("/oauth2-client") + "/oauth2-client".length()));
		
	}
}
