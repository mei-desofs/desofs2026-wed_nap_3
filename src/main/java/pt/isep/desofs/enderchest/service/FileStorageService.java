package pt.isep.desofs.enderchest.service;

import org.apache.tika.Tika;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.config.ApplicationProperties;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;

// IMPORTS QUE FALTAVAM:
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import jakarta.annotation.PostConstruct;

@Service
public class FileStorageService {

    private final Path rootLocation;
    private final ApplicationProperties props;
    private final Tika tika = new Tika();

    public FileStorageService(ApplicationProperties props) {
        this.props = props;
        this.rootLocation = Paths.get(props.storage().basePath());
    }

    @PostConstruct
    public void init() {
        try {
            Files.createDirectories(rootLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize storage location", e);
        }
    }

    public void save(MultipartFile file) {
        try {
            // DEMONSTRAÇÃO DA MITIGAÇÃO T-06 (Web Shell)
            String detectedType = tika.detect(file.getInputStream());
            if (!props.storage().allowedMimeTypes().contains(detectedType)) {
                throw new InvalidFileTypeException(detectedType, String.join(", ", props.storage().allowedMimeTypes()));
            }
            
            // DEMONSTRAÇÃO DA MITIGAÇÃO T-05 (Path Traversal)
            String originalFilename = file.getOriginalFilename();
            if (originalFilename != null && (originalFilename.contains("..") || originalFilename.contains("/"))) {
                throw new PathTraversalAttemptException();
            }

            String filename = UUID.randomUUID().toString();
            Path destinationFile = this.rootLocation.resolve(filename).normalize().toAbsolutePath();

            if (!destinationFile.getParent().equals(this.rootLocation.toAbsolutePath())) {
                throw new PathTraversalAttemptException();
            }

            Files.copy(file.getInputStream(), destinationFile);

        } catch (IOException e) {
            throw new RuntimeException("Failed to store file.", e);
        }
    }
}