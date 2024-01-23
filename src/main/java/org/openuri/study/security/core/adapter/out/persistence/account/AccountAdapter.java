package org.openuri.study.security.core.adapter.out.persistence.account;

import lombok.RequiredArgsConstructor;
import org.openuri.study.security.core.application.port.out.RegisterUserPort;
import org.openuri.study.security.core.common.Adapter;
import org.openuri.study.security.core.domain.Account;

@Adapter
@RequiredArgsConstructor
public class AccountAdapter implements RegisterUserPort {

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
}
