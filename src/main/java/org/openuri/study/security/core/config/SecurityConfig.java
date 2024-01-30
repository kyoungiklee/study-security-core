package org.openuri.study.security.core.config;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.security.common.AjaxLoginAuthenticationEntryPoint;
import org.openuri.study.security.core.application.security.common.FormAuthenticationDetailSource;
import org.openuri.study.security.core.application.security.handler.*;
import org.openuri.study.security.core.application.security.provider.AjaxAutenticationProvider;
import org.openuri.study.security.core.application.security.provider.FormAutenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.annotation.web.configurers.FormLoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
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
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration
@EnableWebSecurity
@Slf4j
@Order(1)
public class SecurityConfig {
    /**
     * {@code HttpSecutiry}를 파라미터로 받아 보안 필터를 설정한다.
     * <p>{@link HttpSecurity} 에서
     *
     * @param http {@link HttpSecurity} 사용자 정의 보안 필터 체인을 설정하기 위한 파라미터이다.
     * @return SecurityFilterChain 사용자 정의 필터체인을 반환한다.
     * @see #webFilterChain(HttpSecurity) (HttpSecurity)
     */
    @Bean
    @Order(1)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {

        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/", "/admin/**", "/error*", "login*").permitAll()
                        .requestMatchers("/messages").hasRole("MANAGER")
                        .requestMatchers("/mypage").hasRole("USER")
                        .requestMatchers("/config").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(formLoginConfigurer())
                .exceptionHandling(exceptionHandlingCustomizer())
                .httpBasic(Customizer.withDefaults())
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        .sessionFixation().newSession())
        ;

        return http.build();
    }

    @Bean
    @Order(0)
    public SecurityFilterChain ajaxFilterChain(HttpSecurity http) throws Exception {
        /*
        인증매니저 생성 (참고)
        AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.authenticationProvider(ajaxAuthenticationProvider());
        authenticationManagerBuilder.parentAuthenticationManager(null);
        authenticationManagerBuilder.build();
         */

        http
                .securityMatcher("/api/**")
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/api/login").permitAll()
                        .requestMatchers("/api/messages").hasRole("MANAGER")
                        .anyRequest().authenticated())
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .accessDeniedHandler(ajaxAccessDeniedHandler())
                        .authenticationEntryPoint(ajaxLoginAuthenticationEntryPoint())
                )
                .sessionManagement(sessionManagement -> sessionManagement
                        .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                        .sessionFixation().newSession())
                //.addFilterBefore(ajaxAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
        ;
        customConfigurer(http);
        return http.build();
    }

    public void customConfigurer(HttpSecurity http) throws Exception {
        http.with(new AjaxLoginConfigure(), (dsl) -> {
            dsl.securityContextRepository(securityContextRepository());
            dsl.successHandlerAjax(ajaxAuthenticationSuccessHandler());
            dsl.failureHandlerAjax(ajaxAutenticationFailureHandler());
            dsl.authenticationManager(authenticationManager());
        });

        System.out.println();
    }

    /**
     * ajax 요청 시 세션에서 {@link SecurityContextRepository}를 가져와 인증을 처리해주는 부분이 정확히 동작되지 않아 아래의
     * 요청을 추가한다
     * <p>
     * 원인은 {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter}의
     * 기본 {@link SecurityContextRepository}가 {@link RequestAttributeSecurityContextRepository}로 설정되어 있어서
     * 세션에서 {@link SecurityContextRepository}를 가져오지 못하는 것이다.
     * <p>
     * {@link org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter} 에서는 
     * {@link SecurityContextRepository}가 {@link DelegatingSecurityContextRepository}로 설정되어 있다
     * <p>
     * {@link DelegatingSecurityContextRepository}는 {@link HttpSessionSecurityContextRepository}와 
     * {@link RequestAttributeSecurityContextRepository}를 파라미터로 사용한다.
     * 세션관리를 위해서는 {@link HttpSessionSecurityContextRepository}를 사용해야 하므로 아래와 같이 설정한다.
     * <p>
     * {@link DelegatingSecurityContextRepository}를 사용하여 {@link HttpSessionSecurityContextRepository}와
     * {@link RequestAttributeSecurityContextRepository}를 사용한다.
     *
     * @return SecurityContextRepository
     */
    @Bean
    public SecurityContextRepository securityContextRepository() {
        return new DelegatingSecurityContextRepository(
                new HttpSessionSecurityContextRepository(),
                new RequestAttributeSecurityContextRepository()
        );
    }

    @Bean
    public AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler() {
        return new AjaxAuthenticationSuccessHandler();
    }

    @Bean
    public AuthenticationFailureHandler ajaxAutenticationFailureHandler() {
        return new AjaxAuthenticationFailureHandler();
    }

    @Bean
    public AjaxLoginAuthenticationEntryPoint ajaxLoginAuthenticationEntryPoint() {
        return new AjaxLoginAuthenticationEntryPoint();
    }


    @Bean
    public AjaxAccessDeniedHandler ajaxAccessDeniedHandler() {
        return new AjaxAccessDeniedHandler();
    }


//    @Bean
//    protected Filter ajaxAuthenticationFilter() {
//
//        AjaxLoginProcessingFilter ajaxAuthenticationFilter = new AjaxLoginProcessingFilter();
//        ajaxAuthenticationFilter.setAuthenticationManager(authenticationManager());
//        ajaxAuthenticationFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler());
//        ajaxAuthenticationFilter.setAuthenticationFailureHandler(ajaxAutenticationFailureHandler());
//        return ajaxAuthenticationFilter;
//    }


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

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(
                formAutenticationProvider(),
                ajaxAuthenticationProvider()
        );
    }

    @Bean
    public AjaxAutenticationProvider ajaxAuthenticationProvider() {
        return new AjaxAutenticationProvider();
    }

    @Bean
    public FormAutenticationProvider formAutenticationProvider() {
        return new FormAutenticationProvider();
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
     *
     * @return {@link Customizer}
     */
    @Bean
    Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandlingCustomizer() {
        return exceptionHandlingConfigurer -> exceptionHandlingConfigurer.accessDeniedHandler(accessDeniedHandler());
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
