package com.substring.auth.auth_app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class AuthAppApplication {

    public static void main(String[] args) {
        ConfigurableApplicationContext context = SpringApplication.run(AuthAppApplication.class, args);
        System.out.println("System.getenv = " + System.getenv("GOOGLE_CLIENT_ID"));

        System.out.println("Spring property = " +
                context.getEnvironment().getProperty("google.client-id"));    }

}
