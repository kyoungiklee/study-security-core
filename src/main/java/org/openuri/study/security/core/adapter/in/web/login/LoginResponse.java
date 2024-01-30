package org.openuri.study.security.core.adapter.in.web.login;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor @AllArgsConstructor
public class LoginResponse {
    @NotNull
    private String username;
    @NotNull
    private String result;

}
