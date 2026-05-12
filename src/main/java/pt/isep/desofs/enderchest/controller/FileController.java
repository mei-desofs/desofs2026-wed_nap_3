package pt.isep.desofs.enderchest.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.service.FileStorageService;

@RestController
@RequestMapping("/api/files")
public class FileController {

    private final FileStorageService fileStorageService;

    // ... (construtor)

    @PostMapping("/upload")
    @PreAuthorize("hasAuthority('ROLE_OWNER') or hasAuthority('ROLE_EDITOR')")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file) {
        // Não precisamos de try-catch aqui. O @ControllerAdvice trata de tudo.
        fileStorageService.save(file);
        return ResponseEntity.status(201).body("File uploaded successfully and scheduled for processing.");
    }
    
    // DEMONSTRAÇÃO DA MITIGAÇÃO T-09 (Role Abuse)
    @GetMapping("/admin-report")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')") // Apenas um ADMIN pode aceder.
    public ResponseEntity<String> getAdminReport() {
        // Se um user normal (OWNER, EDITOR) tentar aceder, o Spring Security lançará
        // uma AccessDeniedException, que será apanhada pelo nosso GlobalSecurityExceptionHandler.
        return ResponseEntity.ok("Admin report data.");
    }
}