package org.openuri.study.security.core.application.service;

import lombok.RequiredArgsConstructor;
import org.openuri.study.security.core.application.port.FindUserPort;
import org.openuri.study.security.core.common.UseCase;
import org.openuri.study.security.core.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Collection;
import java.util.Set;

/**
 * 사용자 인증을 위한 UserDetailsService 구현체
 *
 */
@UseCase
@RequiredArgsConstructor
public class CustomUserDetailService implements UserDetailsService {
    private final FindUserPort findUserPort;

    /**
     * DB 에서 사용자 정보를 조회하여 UserDetails 객체를 생성한다.
     * @param username the username identifying the user whose data is required.
     * @return a fully populated user record (never <code>null</code>)
     * @throws UsernameNotFoundException if the user could not be found or the user has no
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = findUserPort.findByUsername(username);
        return new User(account.getUsername(), account.getPassword(), authorities(account));
    }

    private Collection<? extends GrantedAuthority> authorities(Account account) {

        return Set.of((GrantedAuthority) account::getRole);
    }
}
