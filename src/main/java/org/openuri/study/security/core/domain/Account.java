package org.openuri.study.security.core.domain;


import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = lombok.AccessLevel.PRIVATE)
public class Account {
    private final Long id;
    private final String username;
    private final String password;
    private final String email;
    private final int age;
    private final String role;

    public static Account from( Id id, Username username, Password password, Email email, Age age, Role role) {
        return new Account(id.value(), username.value(), password.value(), email.value(), age.value(), role.value());
    }

    public record Id(Long value) {}

    public record Username(String value) {
        public Username {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    public record Password(String value) {
        public Password {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    public record Email(String value) {
        public Email {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }

    public record Age(int value) {
        public Age {
            if (value < 0) {
                throw new IllegalArgumentException("value must not be negative");
            }
        }
    }

    public record Role(String value) {
        public Role {
            if (value == null) {
                throw new IllegalArgumentException("value must not be null");
            }
        }
    }
}
