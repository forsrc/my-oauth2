package com.forsrc.oauth2.client.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;


@Configuration
//@Order(1)
//@EnableGlobalMethodSecurity(prePostEnabled = true)
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
        	.httpBasic()
        	.and()
        	.oauth2Login()
            ;
    }


}