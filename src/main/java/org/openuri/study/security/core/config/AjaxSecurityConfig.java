package org.openuri.study.security.core.config;

import jakarta.servlet.Filter;
import org.openuri.study.security.core.application.security.filter.AjaxAuthenticationFilter;
import org.openuri.study.security.core.application.security.handler.AjaxAuthenticationFailureHandler;
import org.openuri.study.security.core.application.security.handler.AjaxAuthenticationSuccessHandler;
import org.openuri.study.security.core.application.security.provider.AjaxAutenticationProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@Order(0)
public class AjaxSecurityConfig {

    //filterChain 을 생성한다.
    @Bean
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**")
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/login").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(ajaxAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
        ;
        return http.build();
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }


    @Bean
    protected Filter ajaxAuthenticationFilter() {
        AjaxAuthenticationFilter ajaxAuthenticationFilter = new AjaxAuthenticationFilter();
        ajaxAuthenticationFilter.setAuthenticationManager(authenticationManager());
        ajaxAuthenticationFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
        ajaxAuthenticationFilter.setAuthenticationFailureHandler(ajaxAutenticationFailureHandler());
        return ajaxAuthenticationFilter;
    }

    @Bean
    public AuthenticationFailureHandler ajaxAutenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    /**
     * CustomUserDetailService를 사용하여 사용자 정보를 DB Access를 통해 관리할 수 있다.
     *
     * @return AuthenticationManager
     */
    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(authenticationProvider());
    }


    /**
     * CustomAutenticationProvider를 사용하여 사용자를 인증 처리한다.
     *
     * @return AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider
    authenticationProvider() {
        return new AjaxAutenticationProvider();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}
