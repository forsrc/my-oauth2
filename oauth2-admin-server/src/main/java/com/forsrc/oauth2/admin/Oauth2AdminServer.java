package com.forsrc.oauth2.admin;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

import de.codecentric.boot.admin.server.config.EnableAdminServer;

@EnableDiscoveryClient
@EnableEurekaClient
@EnableAdminServer
@SpringBootApplication
public class Oauth2AdminServer {


    public static void main(String[] args) {
        SpringApplication.run(Oauth2AdminServer.class, args);
    }

}
