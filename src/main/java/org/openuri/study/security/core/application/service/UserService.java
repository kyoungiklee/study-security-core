package org.openuri.study.security.core.application.service;


import lombok.RequiredArgsConstructor;
import org.openuri.study.security.core.application.port.in.RegisterUserCommand;
import org.openuri.study.security.core.application.port.in.RegisterUserUseCase;
import org.openuri.study.security.core.application.port.out.RegisterUserPort;
import org.openuri.study.security.core.common.UseCase;
import org.openuri.study.security.core.domain.Account;
import org.springframework.security.crypto.password.PasswordEncoder;

@UseCase
@RequiredArgsConstructor
public class UserService implements RegisterUserUseCase {
    private final RegisterUserPort registerUserPort;
    private final PasswordEncoder passwordEncoder;
    @Override
    public Account register(RegisterUserCommand command) {

        Account account = Account.from(
                new Account.Id(null),
                new Account.Username(command.getUsername()),
                new Account.Password(passwordEncoder.encode(command.getPassword())),
                new Account.Email(command.getEmail()),
                new Account.Age(command.getAge()),
                new Account.Role(command.getRole())
        );
        return registerUserPort.createAccount(account);
    }
}
