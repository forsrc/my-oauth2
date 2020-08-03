package com.forsrc.oauth2.resource.server.controller;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/hello")
public class HelloController {

	@GetMapping()
	public String hello(Principal principal) {
		return "hello: " + principal.getName();
	}

	@GetMapping("/{name}")
	public String hello(@PathVariable("name") String name, Principal principal) {
		return principal.getName() + ": hello " + name;
	}
}
