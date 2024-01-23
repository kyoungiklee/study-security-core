package org.openuri.study.security.core.application.port.in;

import org.openuri.study.security.core.domain.Account;

public interface RegisterUserUseCase {
    Account register(RegisterUserCommand command);
}
