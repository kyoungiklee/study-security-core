package org.openuri.study.security.core.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.security.common.FormAuthenticationDetailSource;
import org.openuri.study.security.core.application.security.handler.CustomAccessDeniedHandler;
import org.openuri.study.security.core.application.security.handler.CustomAuthenticationFailureHandler;
import org.openuri.study.security.core.application.security.handler.CustomAuthenticationSuccessHandler;
import org.openuri.study.security.core.application.security.provider.FormAutenticationProvider;
import org.openuri.study.security.core.application.service.CustomUserDetailService;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig {


    /**
     * SuccessHandler를 사용하여 로그인 성공 후 이동할 페이지를 설정한다.
     */
    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler() {
        return new CustomAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler authenticationFailureHandler() {
        return new CustomAuthenticationFailureHandler();
    }

    /**
     * formLoginConfigurer를 사용하여 로그인 페이지를 설정한다. {@link HttpSecurity} 에서 fotmLogin() 파라미터로
     * {@link Customizer}를 사용하여 설정할 수 있다.
     *
     * @return Customizer<FormLoginConfigurer < HttpSecurity>>
     */
    @Bean
    public Customizer<FormLoginConfigurer<HttpSecurity>> formLoginConfigurer() {
        return formLoginConfigurer -> formLoginConfigurer
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/")
                .failureUrl("/login?error=true")
                .usernameParameter("username")
                .passwordParameter("password")
                .authenticationDetailsSource(authenticationDetailsSource())
                .failureHandler(authenticationFailureHandler())
                .successHandler(authenticationSuccessHandler())
                .permitAll();
    }

    @Bean
    public AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource() {
        return new FormAuthenticationDetailSource();
    }

    /**
     * AccessDeniedHandler를 사용하여 접근 거부 페이지를 설정한다.
     *
     * @return AccessDeniedHandler
     */
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
        customAccessDeniedHandler.setErrorPage("/denied"); // 접근 거부 페이지를 설정한다.
        return customAccessDeniedHandler;
    }

    /**
     * ExceptionHandlingConfigurer를 사용하여 접근 거부 페이지를 설정한다.
     * @return {@link Customizer}
     */
    @Bean
    Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandlingCustomizer() {
        return exceptionHandlingConfigurer -> exceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
    }

    /**
     * {@code HttpSecutiry}를 파라미터로 받아 보안 필터를 설정한다.
     * <p>{@link HttpSecurity} 에서
     *
     * @param http {@link HttpSecurity} 사용자 정의 보안 필터 체인을 설정하기 위한 파라미터이다.
     * @return SecurityFilterChain 사용자 정의 필터체인을 반환한다.
     * @see #filterChain(HttpSecurity)
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/", "/users").permitAll()
                .requestMatchers("/messages").hasRole("MANAGER")
                .requestMatchers("/mypage").hasRole("USER")
                .requestMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
        ).formLogin(formLoginConfigurer()
        ).exceptionHandling(exceptionHandlingCustomizer())
        ;
        return http.build();
    }

    /**
     * PathRequest를 사용하여 정적 자원의 요청은 Spring Security가 처리하지 않도록 설정한다.
     * <p>
     * {@link WebSecurityCustomizer}를 사용하여 설정할 수 있다.
     *
     * @return WebSecurityCustomizer
     */
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
     *
     * @param userDetailsService CustomUserDetailService
     * @param passwordEncoder    PasswordEncoder
     * @return AuthenticationProvider
     */
    @Bean
    public AuthenticationProvider authenticationProvider(CustomUserDetailService userDetailsService, PasswordEncoder passwordEncoder) {
        return new FormAutenticationProvider(userDetailsService, passwordEncoder);
    }

    /**
     * InMemoryUserDetailsManager를 사용하여 사용자 정보를 관리할 수 있다.
     * spring security 설정 점검을 위해 테스트용으로 사용할 수 있다.
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
