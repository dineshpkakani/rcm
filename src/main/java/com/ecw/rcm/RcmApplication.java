package com.ecw.rcm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;

@SpringBootApplication

public class RcmApplication {

	public static void main(String[] args) {
		SpringApplication.run(RcmApplication.class, args);
	}

}
