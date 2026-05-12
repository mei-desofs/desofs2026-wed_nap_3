package pt.isep.desofs.enderchest.exception.security;

// Específica para a ameaça de Web Shell (T-06)
public class InvalidFileTypeException extends FileUploadException {
    public InvalidFileTypeException(String detectedType, String allowedTypes) {
        super("Security Violation: File type '" + detectedType + "' is not allowed. Permitted types are: " + allowedTypes);
    }
}