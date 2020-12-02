package com.forsrc.oauth2.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.web.context.request.RequestContextListener;

@EnableDiscoveryClient
@EnableEurekaClient
@SpringBootApplication
public class Oauth2ClientApplication {

	@Bean
    @Order(-1000)
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }

	public static void main(String[] args) {
		SpringApplication.run(Oauth2ClientApplication.class, args);
	}

}
