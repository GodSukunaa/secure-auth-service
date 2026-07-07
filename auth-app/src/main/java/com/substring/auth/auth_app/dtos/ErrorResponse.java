package com.substring.auth.auth_app.dtos;

import org.springframework.http.HttpStatus;

public record ErrorResponse(String msg,
                            HttpStatus status) {
}
