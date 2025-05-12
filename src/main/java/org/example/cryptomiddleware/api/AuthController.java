package org.example.cryptomiddleware.api;

import org.example.cryptomiddleware.security.JwtUtil;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @PostMapping("/login")
    public String login(@RequestBody Map<String, String> credentials) {
        String username = credentials.get("username");
        String password = credentials.get("password");
        // Simplified authentication (replace with real user validation)
        if ("admin".equals(username) && "password".equals(password)) {
            return JwtUtil.generateToken(username);
        }
        throw new RuntimeException("Invalid credentials");
    }
}
