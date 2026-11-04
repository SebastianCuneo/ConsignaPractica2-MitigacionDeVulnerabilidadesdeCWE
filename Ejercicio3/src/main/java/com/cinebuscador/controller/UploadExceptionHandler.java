package com.cinebuscador.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Responde de forma controlada (413) cuando un archivo supera el límite de
 * spring.servlet.multipart.*, en lugar de un error 500 con detalles internos.
 */
@ControllerAdvice
public class UploadExceptionHandler {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<String> archivoDemasiadoGrande() {
        return ResponseEntity.status(HttpStatus.PAYLOAD_TOO_LARGE)
                .contentType(MediaType.TEXT_PLAIN)
                .body("El archivo supera el tamaño máximo permitido (2 MB).");
    }
}
