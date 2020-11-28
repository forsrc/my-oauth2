package com.forsrc.oauth2.server.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;

@Configuration
//@EnableWebSecurity
@Order(1)
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${security.user.username}")
	private String username;
	@Value("${security.user.password}")
	private String password;
	@Value("${security.user.roles}")
	private String[] roles;

	@Autowired
    private DataSource dataSource;

	@Override
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
	   return super.authenticationManagerBean();
	}

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//    	http
//        .antMatcher("/**")
//            .authorizeRequests()
//            .antMatchers("/login", "/oauth/authorize", "/oauth/confirm_access", "/oauth/token", "/oauth/token_key", "/oauth/jwks", "/actuator/**", "/static/**", "/error**")
//            .permitAll()
//        .and()
//            .authorizeRequests()
//            .anyRequest()
//            .authenticated()
//        .and()
//            .formLogin()
//            .permitAll()
//        .and()
//        	.logout()
//        	.invalidateHttpSession(true)
//        	.clearAuthentication(true)
//    		.deleteCookies("AUTH_SERVER_SESSION")
//    		.permitAll()
//        ;
    	
    	http.requestMatchers()
			.antMatchers("/login", "/logout", "/oauth/logout", "/oauth/authorize", "/oauth/token_key", "/actuator/**", "/static/**", "/error**")
			.and()
			.authorizeRequests()
			.antMatchers("/", "/login", "/login?**", "/oauth/token", "/oauth/jwks")
			.permitAll()
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
			.successHandler(authenticationSuccessHandler())
			.permitAll()
			;
    	

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//            .withUser(username)
//            .password(passwordEncoder().encode(password))
//            .roles(roles);
       
        auth
        .jdbcAuthentication()
        .dataSource(dataSource)
        .passwordEncoder(passwordEncoder())
        .usersByUsernameQuery("SELECT username,password,enabled FROM users WHERE username = ?")
        .authoritiesByUsernameQuery("SELECT username,authority FROM authorities WHERE username = ?")
        ;
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        // /oauth/token
        auth
                .userDetailsService(userDetailsService())
                .passwordEncoder(passwordEncoder());
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    

	@Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new SimpleUrlAuthenticationSuccessHandler() {
			


			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {

				
				DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");

				if (defaultSavedRequest != null && !response.isCommitted()) {
					getRedirectStrategy().sendRedirect(request, response, defaultSavedRequest.getRedirectUrl());
					return;
				}

				String targetUrl = determineTargetUrl(request, response, authentication);
				if (!response.isCommitted()) {
					super.getRedirectStrategy().sendRedirect(request, response, targetUrl);
				}
				clearAuthenticationAttributes(request);

				
			}
		};
	}

}