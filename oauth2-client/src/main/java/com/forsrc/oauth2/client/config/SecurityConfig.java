package com.forsrc.oauth2.client.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
@Order(1)
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableOAuth2Sso
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
    	http.antMatcher("/**")
        	.authorizeRequests()
        	.antMatchers("/", "/login**", "/error", "/actuator/**")
        	.permitAll()
        	.anyRequest()
        	.authenticated()
        	.and()
        	.logout()
        	.invalidateHttpSession(true)
        	.clearAuthentication(true)
        	.logoutSuccessUrl("/login?logout")
        	.deleteCookies("CLIENT_SESSION")
        	.permitAll()
        	.and()
        	.csrf()
        	.disable()
        	.httpBasic();
            ;
    }


}