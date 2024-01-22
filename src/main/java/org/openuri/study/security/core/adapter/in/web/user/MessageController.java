package org.openuri.study.security.core.adapter.in.web.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MessageController {

    @GetMapping("/messages")
    public String message() {
        return "user/messages";
    }
}
