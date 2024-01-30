package org.openuri.study.security.core.config;

import jakarta.validation.constraints.NotNull;
import org.apache.catalina.core.ApplicationContext;
import org.openuri.study.security.core.application.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

public class AjaxLoginConfigure extends AbstractHttpConfigurer<AjaxLoginConfigure, HttpSecurity> {

    
    private AuthenticationSuccessHandler successHandler;
    
    private AuthenticationFailureHandler failureHandler;
    
    private AuthenticationManager authenticationManager;
    
    private SecurityContextRepository securityContextRepository;

    public void init(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);
    }

    public void configure(HttpSecurity http) throws Exception {
        if(authenticationManager == null){
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
        }

        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter();
        filter.setSecurityContextRepository(securityContextRepository);
        filter.setAuthenticationManager(authenticationManager);
        filter.setAuthenticationSuccessHandler(successHandler);
        filter.setAuthenticationFailureHandler(failureHandler);

        SessionAuthenticationStrategy sessionAuthenticationStrategy = http.getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }

        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            filter.setRememberMeServices(rememberMeServices);
        }

        http.setSharedObject(AjaxLoginProcessingFilter.class, filter);

        filter.afterPropertiesSet();
        http.addFilterBefore(postProcess(filter), UsernamePasswordAuthenticationFilter.class);
    }

    public AjaxLoginConfigure successHandlerAjax(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }

    public AjaxLoginConfigure failureHandlerAjax(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }

    public AjaxLoginConfigure authenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }
    
    public AjaxLoginConfigure securityContextRepository(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
        return this;
    }
}
