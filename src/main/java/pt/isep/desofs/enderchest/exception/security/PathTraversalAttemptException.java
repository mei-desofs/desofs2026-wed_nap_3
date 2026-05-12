package pt.isep.desofs.enderchest.exception.security;

// Específica para a ameaça de Path Traversal (T-05)
public class PathTraversalAttemptException extends FileUploadException {
    public PathTraversalAttemptException() {
        super("Security Violation: Path Traversal attempt detected and blocked.");
    }
}