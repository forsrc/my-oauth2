package com.forsrc.oauth2.server.config;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.util.UriComponentsBuilder;

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
//        http
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
//            .logout()
//            .invalidateHttpSession(true)
//            .clearAuthentication(true)
//            .deleteCookies("AUTH_SERVER_SESSION")
//            .permitAll()
//        ;
 
        

        http.requestMatchers()
            .antMatchers("/login", "/login?**", "/login/**", "/logout", "/oauth/logout", "/oauth/authorize", "/oauth/token_key", "/actuator/**", "/static/**", "/error**")
            .and()
            .authorizeRequests()
            .antMatchers("/", "/login", "/login?error", "/login?logout", "/oauth/token", "/oauth/jwks")
            .permitAll()
            .anyRequest()
            .authenticated()
            .and()
            .formLogin()
            .successHandler(authenticationSuccessHandler())
            .failureHandler(authenticationFailureHandler(), "/login?error")
            .permitAll()
            .and()
            .logout()
            //.logoutSuccessUrl("/login?logout")
            //.logoutSuccessHandler(logoutSuccessHandler(), "/login?logout")
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("AUTH_SERVER_SESSION")
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
                
                String gatewayOauth2Server = request.getHeader("gateway_oauth2_server");
                if (defaultSavedRequest == null && gatewayOauth2Server != null) {
                    String loginUri = UriComponentsBuilder.fromUriString(gatewayOauth2Server).build().toString();
                    super.getRedirectStrategy().sendRedirect(request, response, loginUri);
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

    
    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler("/login?error")  {
            private String defaultFailureUrl = "/login?error";
            private boolean forwardToDestination = false;
            private boolean allowSessionCreation = true;
                
            @Override
            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                    AuthenticationException exception) throws IOException, ServletException {
                if (defaultFailureUrl == null) {
                    logger.debug("No failure URL set, sending 401 Unauthorized error");
    
                    response.sendError(HttpStatus.UNAUTHORIZED.value(),
                        HttpStatus.UNAUTHORIZED.getReasonPhrase());
                }
                else {
                    saveException(request, exception);

                    request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
    
                    request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION,
                                    exception);
                    
                    request.setAttribute("loginError", exception.getMessage());
                    
    

                    if (forwardToDestination) {
                        logger.debug("Forwarding to " + defaultFailureUrl);
    
                        request.getRequestDispatcher(defaultFailureUrl)
                                .forward(request, response);
                    }
                    else {
                        logger.debug("Redirecting to " + defaultFailureUrl);
                        String gatewayOauth2Server = request.getHeader("gateway_oauth2_server");
                        if (gatewayOauth2Server != null) {
                            String loginUri = UriComponentsBuilder.fromUriString(gatewayOauth2Server).path("/login?error").build().toString();
                            super.getRedirectStrategy().sendRedirect(request, response, loginUri);
                            return;
                        }
    
                        super.getRedirectStrategy().sendRedirect(request, response, defaultFailureUrl);
                    }
                }
            }
        };
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {

        return new SimpleUrlLogoutSuccessHandler() {

            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                    Authentication authentication) throws IOException, ServletException {
                
                String gatewayOauth2Server = request.getHeader("gateway_oauth2_server");
                if (gatewayOauth2Server != null) {
                    String loginUri = UriComponentsBuilder.fromUriString(gatewayOauth2Server).path("/login?logout").build().toString();
                    super.getRedirectStrategy().sendRedirect(request, response, loginUri);
                    return;
                }
                super.onLogoutSuccess(request, response, authentication);
                
            }
            
        };
    }

    private final static class ExactUrlRequestMatcher implements RequestMatcher {
        private String processUrl;

        private ExactUrlRequestMatcher(String processUrl) {
            this.processUrl = processUrl;
        }

        public boolean matches(HttpServletRequest request) {
            String uri = request.getRequestURI();
            String query = request.getQueryString();

            if (query != null) {
                uri += "?" + query;
            }

            if ("".equals(request.getContextPath())) {
                return uri.equals(processUrl);
            }

            return uri.equals(request.getContextPath() + processUrl);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("ExactUrl [processUrl='").append(processUrl).append("']");
            return sb.toString();
        }
    }

}