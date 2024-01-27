package org.openuri.study.security.core.application.security.provider;

import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.security.common.FormWebAuthenticationDetails;
import org.openuri.study.security.core.application.service.AccountContext;
import org.openuri.study.security.core.application.service.CustomUserDetailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 사용자 인증을 위한 AuthenticationProvider 구현체
 * <p> FormAuthenticationProvider를 이용하여 커스터마징된 인증을 구현한다.
 */
@Component
@Slf4j
public class FormAutenticationProvider implements AuthenticationProvider {
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
        // authentication 객체로부터 아이디와 비밀번호를 조회한다.
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // username, password를 이용해서 인증을 진행한다.
        AccountContext accountContext;
        try {
            accountContext = (AccountContext) customUserDetailService.loadUserByUsername(username);
        } catch (Exception e) {
            log.info("exception: {}", e.getMessage());

            throw new UsernameNotFoundException("존재하지 않는 사용자입니다.");
        }
        log.info("accountContext: {}", accountContext);

        boolean matches = passwordEncoder.matches(password, accountContext.getPassword());
        log.info("matches: {}", matches);
        if (!matches) {
            throw new BadCredentialsException("비밀번호가 일치하지 않습니다.");
        }
        // 추가 파라미터를 받아 인증을 진행한다. FormWebAuthenticationDetails에서 추가 파라미터를 받는다.
        FormWebAuthenticationDetails formWebAuthenticationDetails = (FormWebAuthenticationDetails) authentication.getDetails();
        String secretKey = formWebAuthenticationDetails.getSecretKey();
        if (!"secret".equals(secretKey)) { // secretKey가 일치하지 않으면 인증 실패(LoginForm에서 설정한 secret_key 파라미터가 없거나 secret가 아닌 경우
            throw new InsufficientAuthenticationException("인증정보가 확인되지 않습니다.");
        }
        // 인증이 성공하면 Authentication 객체를 리턴한다.
        return new UsernamePasswordAuthenticationToken(accountContext.getAccount(), password, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 파라미터가 UsernamePasswordAuthenticationToken 타입인지 확인

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);

    }
}

