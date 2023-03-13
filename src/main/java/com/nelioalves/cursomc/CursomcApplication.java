package com.nelioalves.cursomc;

import java.util.Date;
import java.util.TimeZone;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class CursomcApplication implements CommandLineRunner {
	
	public static void main(String[] args) {
		TimeZone.setDefault(TimeZone.getTimeZone("UTC"));   // It will set UTC timezone
		SpringApplication.run(CursomcApplication.class, args);
		Date now = new Date(System.currentTimeMillis());
		System.out.println("Data pré definição de Timezone" + now.toString());
		System.out.println(TimeZone.getDefault());
        System.out.println("Spring boot application running in UTC timezone :"+new Date());   // It will print UTC timezone
	}

	@Override
	public void run(String... args) throws Exception {		
	}
}
