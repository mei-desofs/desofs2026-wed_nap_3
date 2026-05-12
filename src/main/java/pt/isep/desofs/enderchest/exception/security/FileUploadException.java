package pt.isep.desofs.enderchest.exception.security;

// Exceção base para todos os problemas de upload
public class FileUploadException extends RuntimeException {
    public FileUploadException(String message) {
        super(message);
    }
}