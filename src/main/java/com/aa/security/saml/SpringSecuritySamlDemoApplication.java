package com.aa.security.saml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
public class SpringSecuritySamlDemoApplication extends org.springframework.boot.web.support.SpringBootServletInitializer {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecuritySamlDemoApplication.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(SpringSecuritySamlDemoApplication.class);
    }

}
