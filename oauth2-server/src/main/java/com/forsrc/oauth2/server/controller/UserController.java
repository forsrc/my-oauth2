package com.forsrc.oauth2.server.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	@GetMapping("/me")
	@PreAuthorize("isAuthenticated()")
	public Principal user(Principal principal) {
		System.out.println("-> Principal: " + principal);
		return principal;
	}

	@GetMapping("/test")
	public String test() {
		System.out.println("-> test");
		return "test";
	}
}