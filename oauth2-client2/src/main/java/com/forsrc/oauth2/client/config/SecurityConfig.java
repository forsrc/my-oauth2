package com.forsrc.oauth2.client.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;


@Configuration
@Order(1)
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {

    	http
		.authorizeRequests(a -> a
			.antMatchers("/", "/error", "/webjars/**").permitAll()
			.anyRequest().authenticated()
		)
//		.exceptionHandling(e -> e
//			.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
//		)
		.csrf(c -> c
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
		)
		.logout(l -> l
				.invalidateHttpSession(true)
	        	.clearAuthentication(true)
	        	.logoutSuccessUrl("/?logout")
	        	.deleteCookies("CLIENT_SESSION").permitAll()
		)
		.oauth2Login();
    }


}