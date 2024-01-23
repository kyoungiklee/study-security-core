package org.openuri.study.security.core.application.port.out;

import org.openuri.study.security.core.domain.Account;

public interface RegisterUserPort {

    Account createAccount(Account account);
}
