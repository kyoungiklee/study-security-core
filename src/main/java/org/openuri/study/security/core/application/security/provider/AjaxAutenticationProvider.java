package org.openuri.study.security.core.application.security.provider;

import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.security.token.AjaxAuthenticationToken;
import org.openuri.study.security.core.application.service.AccountContext;
import org.openuri.study.security.core.application.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AjaxAutenticationProvider implements AuthenticationProvider {

    private CustomUserDetailService customUserDetailService;
    private PasswordEncoder passwordEncoder;

    @Autowired
    public void setCustomUserDetailService(CustomUserDetailService customUserDetailService) {
        this.customUserDetailService = customUserDetailService;
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        //username, password 로그 기록
        log.info("username: {}", username);
        log.info("password: {}", password);
        AccountContext accountContext = (AccountContext) customUserDetailService.loadUserByUsername(username);

        //password check
        boolean matches = passwordEncoder.matches(password, accountContext.getPassword());

        //password가 일치하지 않으면 BadCredentialsException 발생
        if (!matches) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }
        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountContext.getAccount()
                , null, accountContext.getAuthorities());

        /*SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(ajaxAuthenticationToken);
        SecurityContextHolder.setContext(context);*/

        return ajaxAuthenticationToken;

    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
