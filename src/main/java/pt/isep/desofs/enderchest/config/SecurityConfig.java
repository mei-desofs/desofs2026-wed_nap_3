package pt.isep.desofs.enderchest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Essencial para o RBAC com @PreAuthorize
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Desativar CSRF, pois a API é stateless e não usa cookies para autenticação.
            .csrf(csrf -> csrf.disable())

            // Garantir que a API é stateless, não criando sessões HTTP.
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Configurar as regras de autorização para todos os endpoints.
            .authorizeHttpRequests(authz -> authz
                // Permitir acesso público a Swagger/OpenAPI
                .requestMatchers(
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**",
                    "/webjars/**"
                ).permitAll()
                // Por defeito, todas as requests exigem um utilizador autenticado.
                .anyRequest().authenticated()
            )

            // Configurar a validação de JWTs (OAuth2 Resource Server).
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {})); 

        return http.build();
    }
}