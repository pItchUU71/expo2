package school.hei.asa.endpoint.rest.security;

import java.time.Instant;
import java.util.List;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import school.hei.asa.model.Worker;
import school.hei.asa.repository.WorkerRepository;

@Configuration
@EnableWebSecurity
@Slf4j
@Profile("noauth")
public class NoAuthSecurityConfig {

  private static final String DEV_EMAIL = "noauth@dev.local";

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http, WorkerRepository workerRepository)
      throws Exception {
    http.csrf(csrf -> csrf.disable())
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
        .addFilterBefore(
            (request, response, chain) -> {
              if (SecurityContextHolder.getContext().getAuthentication() == null) {
                var worker =
                    workerRepository
                        .findByEmail(DEV_EMAIL)
                        .orElseGet(
                            () -> {
                              log.info("Creating dev worker for noauth profile");
                              var w =
                                  new Worker(
                                      "DEV",
                                      "Dev User",
                                      DEV_EMAIL,
                                      "Dev User",
                                      "",
                                      "",
                                      "",
                                      "");
                              workerRepository.save(w);
                              return w;
                            });
                var idToken =
                    OidcIdToken.withTokenValue("noauth-token")
                        .issuer("https://noauth")
                        .subject(worker.code())
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(86400))
                        .claim("email", worker.email())
                        .build();
                var principal =
                    new DefaultOidcUser(
                        List.of(new SimpleGrantedAuthority("ROLE_USER")), idToken);
                var authentication =
                    new org.springframework.security.authentication
                        .UsernamePasswordAuthenticationToken(
                        principal, null, principal.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                log.info("Noauth authentication set for worker: {}", worker.code());
              }
              chain.doFilter(request, response);
            },
            UsernamePasswordAuthenticationFilter.class);
    return http.build();
  }
}
