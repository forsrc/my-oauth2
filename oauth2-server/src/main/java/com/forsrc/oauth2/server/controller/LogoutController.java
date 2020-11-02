package com.forsrc.oauth2.server.controller;

import java.io.IOException;
import java.security.Principal;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.ResponseEntity;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class LogoutController {

	@RequestMapping(path = "/oauth/logout")
	// @PreAuthorize("isAuthenticated()")
	public ResponseEntity<Void> user(HttpServletRequest request, HttpServletResponse response, Principal principal, String referer) {
		String user = principal == null ? "NO USER" : principal.getName();
		new SecurityContextLogoutHandler().logout(request, null, null);
		try {
			response.sendRedirect(referer != null ? referer : request.getHeader("referer"));
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("-> logout: " + principal);
		return ResponseEntity.ok().header("logout_user", user).build();
	}

}