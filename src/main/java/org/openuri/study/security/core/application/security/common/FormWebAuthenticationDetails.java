package org.openuri.study.security.core.application.security.common;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

/**
 * {@link WebAuthenticationDetails}를 상속받아 추가 파라미터를 받을 수 있도록 한다.
 * FormAuthenticationProvider에서 사용한다.
 */
@Slf4j
@Getter
public class FormWebAuthenticationDetails extends WebAuthenticationDetails {
    private final String secretKey;

    public FormWebAuthenticationDetails(HttpServletRequest request) {
        super(request);
        secretKey = request.getParameter("secret_key");

    }
}
