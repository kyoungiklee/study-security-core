package org.openuri.study.security.core.config;

import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.service.CustomAutenticationProvider;
import org.openuri.study.security.core.application.service.CustomUserDetailService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/", "/users").permitAll()
                .requestMatchers("/messages").hasRole("MANAGER")
                .requestMatchers("/mypage").hasRole("USER")
                .requestMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        ).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public WebSecurityCustomizer ignoringCustomizer() {
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    /**
     * CustomUserDetailService를 사용하여 사용자 정보를 DB Access를 통해 관리할 수 있다.
     *
     * @param userDetailsService UserDetailsService
     * @param passwordEncoder    PasswordEncoder
     * @return AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager(CustomUserDetailService userDetailsService, PasswordEncoder passwordEncoder) {
        AuthenticationProvider authenticationProvider = authenticationProvider(userDetailsService, passwordEncoder);
        return new ProviderManager(authenticationProvider);
    }


    /**
     * CustomAutenticationProvider를 사용하여 사용자를 인증 처리한다.
     * @param userDetailsService CustomUserDetailService
     * @param passwordEncoder PasswordEncoder
     * @return AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailService userDetailsService, PasswordEncoder passwordEncoder) {
        return new CustomAutenticationProvider(userDetailsService, passwordEncoder);
    }

    /**
     * InMemoryUserDetailsManager를 사용하여 사용자 정보를 관리할 수 있다.
     *
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
                .username("user")
                .password(passwordEncoder().encode("1234"))
                .roles("USER")
                .build();
        UserDetails manager = User.builder()
                .username("manager")
                .password(passwordEncoder().encode("1234"))
                .roles("MANAGER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(passwordEncoder().encode("1234"))
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user, manager, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
