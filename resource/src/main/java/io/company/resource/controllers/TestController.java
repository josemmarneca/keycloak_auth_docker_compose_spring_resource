package io.company.resource.controllers;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)

@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint(HttpServletRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication.getDetails();
        return new ResponseEntity<>("Public Endpoint", HttpStatus.ACCEPTED);
    }

    @GetMapping("/user")
    public ResponseEntity<String> userEndpoint() {

        return new ResponseEntity<>("User Endpoint", HttpStatus.ACCEPTED);
    }

    @GetMapping("/moderator")
    public ResponseEntity<String>  moderatorAccess() {
        return new ResponseEntity<>("Moderator Endpoint", HttpStatus.ACCEPTED);
    }

    @GetMapping("/admin")
    public ResponseEntity<String> adminEndpoint() {
        return new ResponseEntity<>("Admin Endpoint", HttpStatus.ACCEPTED);
    }
}
