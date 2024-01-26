package org.openuri.study.security.core.application.security.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class FormAuthenticationDetailSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {

        @Override
        public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
            return new FormWebAuthenticationDetails(request);
        }
}