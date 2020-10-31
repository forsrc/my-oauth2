package com.forsrc.oauth2.client.controller;

import java.security.Principal;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@GetMapping("/user/me")
	public Principal user(Principal principal) {
		return principal;
	}
	
	@GetMapping("/me")
	public OAuth2User user(@AuthenticationPrincipal OAuth2User principal) {
		return principal;
	}
}