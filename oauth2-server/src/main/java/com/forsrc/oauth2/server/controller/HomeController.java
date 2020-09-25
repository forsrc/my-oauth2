package com.forsrc.oauth2.server.controller;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HomeController {

	@GetMapping()
	@PreAuthorize("hasRole('USER')")
	public Principal user(Principal principal) {
		System.out.println("-> Principal: " + principal);
		return principal;
	}

	
	@GetMapping("admin")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public Principal admin(Principal principal) {
		System.out.println("-> Principal: " + principal);
		return principal;
	}

}
