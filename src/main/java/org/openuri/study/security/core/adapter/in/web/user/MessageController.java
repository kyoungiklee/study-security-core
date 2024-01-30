package org.openuri.study.security.core.adapter.in.web.user;


import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping("/messages")
    public String message() {
        return "user/messages";
    }

}
