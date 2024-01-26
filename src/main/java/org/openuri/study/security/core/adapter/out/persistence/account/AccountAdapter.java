package org.openuri.study.security.core.adapter.out.persistence.account;

import lombok.RequiredArgsConstructor;
import org.openuri.study.security.core.application.port.out.FindUserPort;
import org.openuri.study.security.core.application.port.out.RegisterUserPort;
import org.openuri.study.security.core.common.Adapter;
import org.openuri.study.security.core.domain.Account;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Adapter
@RequiredArgsConstructor
public class AccountAdapter implements RegisterUserPort, FindUserPort {

    private final AccountRepository accountRepository;
    @Override
    public Account createAccount(Account account) {
        AccountEntity save = accountRepository.save(AccountEntity.builder()
                .username(account.getUsername())
                .password(account.getPassword())
                .email(account.getEmail())
                .role(account.getRole())
                .build());

        return Account.from(
                new Account.Id(save.getId()),
                new Account.Username(save.getUsername()),
                new Account.Password(save.getPassword()),
                new Account.Email(save.getEmail()),
                new Account.Age(save.getAge()),
                new Account.Role(save.getRole())
        );
    }

        @Override
        public Account findByUsername(String username) {
            AccountEntity accountEntity = accountRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("Not found username: " + username));

            return Account.from(
                    new Account.Id(accountEntity.getId()),
                    new Account.Username(accountEntity.getUsername()),
                    new Account.Password(accountEntity.getPassword()),
                    new Account.Email(accountEntity.getEmail()),
                    new Account.Age(accountEntity.getAge()),
                    new Account.Role(accountEntity.getRole())
            );
        }

}
