package pt.isep.desofs.enderchest.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true) // Essencial para o RBAC com @PreAuthorize
public class SecurityConfig {

    // Namespace do claim customizado configurado na Action do Auth0.
    // Corresponde ao identifier da API: https://enderchest-api
    private static final String ROLES_CLAIM = "https://enderchest-api/roles";

    @Bean
    public RateLimiterFilter rateLimiterFilter(ApplicationProperties properties) {
        return new RateLimiterFilter(properties);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
                                                   RateLimiterFilter rateLimiterFilter) throws Exception {
        http
                // Desativar CSRF — API stateless, não usa cookies para autenticação (SDR-01)
                .csrf(csrf -> csrf.disable())

                // Garantir que a API é stateless — sem sessões HTTP (SDR-01)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Configurar regras de autorização
                .authorizeHttpRequests(authz -> authz
                        // Permitir acesso público a Swagger/OpenAPI
                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/webjars/**"
                        ).permitAll()
                        // Todas as outras requests exigem autenticação
                        .anyRequest().authenticated()
                )

                // Configurar validação de JWTs com conversor customizado para Auth0
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                )

                // Rate limiting filter runs after authentication is resolved (SDR-10)
                .addFilterAfter(rateLimiterFilter, BearerTokenAuthenticationFilter.class);

        return http.build();
    }
    
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Ler roles do claim customizado injetado pela Action do Auth0
            List<String> roles = jwt.getClaimAsStringList(ROLES_CLAIM);

            if (roles == null || roles.isEmpty()) {
                return Collections.emptyList();
            }

            // Converter "OWNER" -> "ROLE_OWNER" para compatibilidade com @PreAuthorize
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toList());
        });

        return converter;
    }
}