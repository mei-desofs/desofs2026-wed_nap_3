package pt.isep.desofs.enderchest.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * OpenAPI/Swagger configuration for EnderChest.
 * Provides API documentation with contact info, license, and server details.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("EnderChest API")
                .version("1.0.0")
                .description("Secure collaborative file storage system with hierarchical folders, " +
                    "version control, and access sharing capabilities. " +
                    "All endpoints require OAuth2 Bearer token authentication (except /actuator/health and /v3/api-docs).")
                .contact(new Contact()
                    .name("EnderChest Development Team")
                    .email("dev@enderchest.local"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")))
            .addServersItem(new Server()
                .url("http://localhost:8080")
                .description("Development Server"))
            .addServersItem(new Server()
                .url("https://api.enderchest.local")
                .description("Production Server"));
    }
}
