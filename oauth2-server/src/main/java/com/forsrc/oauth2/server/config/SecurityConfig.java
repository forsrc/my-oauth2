package com.forsrc.oauth2.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@Order(-20)
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${security.user.username}")
	private String username;
	@Value("${security.user.password}")
	private String password;
	@Value("${security.user.roles}")
	private String[] roles;

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
	   return super.authenticationManagerBean();
	}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
        .antMatcher("/**").authorizeRequests()
        .and()
        .requestMatchers()
        .antMatchers("/", "/login", "/logout", "/error", "/oauth/authorize", "/oauth/confirm_access")
        .and()
        .authorizeRequests()
        .antMatchers("/oauth/token", "/actuator/**", "/static/**")
        .permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .logout()
        .permitAll()
        .and()
        .formLogin()
        ;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//            .withUser(username)
//            .password(passwordEncoder().encode(password))
//            .roles(roles);
       
        auth.inMemoryAuthentication()
        	.withUser("forsrc")
        	.password(passwordEncoder().encode("forsrc"))
        	.roles("USER", "ADMIN");
    }
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}