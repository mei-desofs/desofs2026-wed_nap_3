package pt.isep.desofs.enderchest.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import pt.isep.desofs.enderchest.exception.security.FileUploadException;

@ControllerAdvice
public class GlobalSecurityExceptionHandler {

    private static final Logger securityLogger = LoggerFactory.getLogger("SecurityAuditLogger");

    // Apanha TODAS as nossas exceções de segurança customizadas
    @ExceptionHandler(FileUploadException.class)
    public ResponseEntity<String> handleFileUploadSecurityException(FileUploadException ex) {
        // Log detalhado para o SIEM com a razão da falha (essencial para a auditoria)
        securityLogger.warn("Blocked a malicious file upload attempt. Reason: {}", ex.getMessage());
        
        // Resposta genérica para o cliente (ameaça T-04: Mitigação de Information Disclosure)
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid request. The file could not be processed.");
    }

    // Apanha falhas de autorização (RBAC) do Spring Security
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException ex) {
        // Log de segurança para tentativas de escalada de privilégios (ameaça T-09: Role Abuse)
        // DEV_TEAM: Adicionar aqui o ID do utilizador autenticado para um log mais rico.
        securityLogger.warn("Authorization Failure: A user attempted to access a resource without permission. {}", ex.getMessage());

        // Resposta HTTP 403 Forbidden
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access Denied.");
    }

    // Apanha todas as outras exceções para evitar a fuga de stack traces
    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleGenericException(Exception ex) {
        // Log genérico de erro
        securityLogger.error("An unexpected server error occurred.", ex);
        
        // Resposta genérica para o cliente
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An internal error occurred.");
    }
}