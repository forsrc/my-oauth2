package com.forsrc.oauth2.client.config;

import java.io.IOException;
import java.util.Collections;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.PortResolver;
import org.springframework.security.web.PortResolverImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;


@Configuration
@Order(1)
//@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Value("${spring.security.oauth2.client.provider.my-oauth2.logout-uri}")
	private String oauth2ServerLogoutUri;
	
    @Override
    public void configure(HttpSecurity http) throws Exception {
    	PortMapperImpl portMapper = new PortMapperImpl();
    	portMapper.setPortMappings(Collections.singletonMap("8080", "8080"));

    	http
    	.portMapper()
    	.portMapper(portMapper)
    	.and()
		.authorizeRequests(a -> a
			.antMatchers("/", "/login", "/error", "/webjars/**").permitAll()
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
	        	.logoutSuccessUrl(oauth2ServerLogoutUri)
	        	.deleteCookies("CLIENT_SESSION").permitAll()
		)
		.oauth2Login()
		.successHandler(authenticationSuccessHandler())
		.failureHandler(authenticationFailureHandler())
		.and()
        .requestCache()
        .requestCache(requestCache())
		;
    }
    

    @Bean
	public  PortMapper portMapper() {
    	PortMapperImpl portMapper = new PortMapperImpl();
    	portMapper.setPortMappings(Collections.singletonMap("8080", "8080"));
    	PortResolverImpl portResolver = new PortResolverImpl();
    	portResolver.setPortMapper(portMapper);
        return portMapper;
    }
    
    @Bean
 	public  PortResolver portResolver() {
     	PortResolverImpl portResolver = new PortResolverImpl();
     	portResolver.setPortMapper(portMapper());
         return portResolver;
     }

    @Bean
	public  RequestCache requestCache() {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setPortResolver(portResolver());
        return requestCache;
    }

    @Bean
	public AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new SimpleUrlAuthenticationSuccessHandler() {
			


			@Override
			public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
					Authentication authentication) throws IOException, ServletException {

				
				DefaultSavedRequest defaultSavedRequest = (DefaultSavedRequest) request.getSession().getAttribute("SPRING_SECURITY_SAVED_REQUEST");

				if (defaultSavedRequest != null && !response.isCommitted()) {
					
					String gatewayOauth2Client = request.getHeader("gateway_oauth2_client");
					String oauth2Client = "/oauth2-client";
					String redirectUrl = defaultSavedRequest.getRedirectUrl();
					if (gatewayOauth2Client != null && redirectUrl.indexOf(oauth2Client) > 0) {
						String path = redirectUrl.substring(redirectUrl.indexOf(oauth2Client) + oauth2Client.length());
								
						redirectUrl = UriComponentsBuilder.fromUriString(gatewayOauth2Client).path(path).build().toString();
						getRedirectStrategy().sendRedirect(request, response, redirectUrl);
						return;
					}

					getRedirectStrategy().sendRedirect(request, response, redirectUrl);
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
		return new SimpleUrlAuthenticationFailureHandler() {
			
			private String defaultFailureUrl;
			private boolean forwardToDestination;
			private RedirectStrategy redirectStrategy;
			
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

					if (forwardToDestination) {
						logger.debug("Forwarding to " + defaultFailureUrl);

						request.getRequestDispatcher(defaultFailureUrl)
								.forward(request, response);
					}
					else {
						logger.debug("Redirecting to " + defaultFailureUrl);
						redirectStrategy.sendRedirect(request, response, defaultFailureUrl);
					}
				}
			}


			@Override
			public void setDefaultFailureUrl(String defaultFailureUrl) {
				super.setDefaultFailureUrl(defaultFailureUrl);
				Assert.isTrue(UrlUtils.isValidRedirectUrl(defaultFailureUrl),
						() -> "'" + defaultFailureUrl + "' is not a valid redirect URL");
				this.defaultFailureUrl = defaultFailureUrl;
			}

			@Override
			public void setUseForward(boolean forwardToDestination) {
				super.setUseForward(forwardToDestination);
				this.forwardToDestination = forwardToDestination;
			}

			@Override
			public void setRedirectStrategy(RedirectStrategy redirectStrategy) {
				super.setRedirectStrategy(redirectStrategy);
				this.redirectStrategy = redirectStrategy;
			}
		};
	}

}