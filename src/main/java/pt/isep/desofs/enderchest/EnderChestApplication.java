package pt.isep.desofs.enderchest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import pt.isep.desofs.enderchest.config.ApplicationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ApplicationProperties.class) 
public class EnderChestApplication {

    public static void main(String[] args) {
        
        SpringApplication.run(EnderChestApplication.class, args);
    }

}