package org.openuri.study.security.core.adapter.in.web.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {
    @GetMapping("/mypage")
    public String user() {
        return "user/mypage";
    }
}
