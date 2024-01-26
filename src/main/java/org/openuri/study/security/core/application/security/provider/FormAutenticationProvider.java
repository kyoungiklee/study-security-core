package org.openuri.study.security.core.application.security.provider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.openuri.study.security.core.application.security.common.FormWebAuthenticationDetails;
import org.openuri.study.security.core.application.service.CustomUserDetailService;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@Slf4j
@RequiredArgsConstructor
public class FormAutenticationProvider implements AuthenticationProvider {
    private final CustomUserDetailService customUserDetailService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // authentication 객체로부터 아이디와 비밀번호를 조회한다.
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();

        // username, password를 이용해서 인증을 진행한다.
        UserDetails userDetails;
        try {
            userDetails = customUserDetailService.loadUserByUsername(username);
        } catch (Exception e) {
            throw new UsernameNotFoundException("존재하지 않는 사용자입니다.");
        }
        log.info("userDetails: {}", userDetails);

        boolean matches = passwordEncoder.matches(password, userDetails.getPassword());
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
        return new UsernamePasswordAuthenticationToken(username, password, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 파라미터가 UsernamePasswordAuthenticationToken 타입인지 확인

        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);

    }
}

