package com.forsrc.oauth2.server.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

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
			.antMatchers("/", "/oauth/token", "/oauth/jwks")
			.permitAll()
			.anyRequest()
			.authenticated()
			.and()
			.formLogin()
			.permitAll();
    	

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
    

}