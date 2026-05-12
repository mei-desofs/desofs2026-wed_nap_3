package pt.isep.desofs.enderchest.service;

import org.apache.tika.Tika;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import pt.isep.desofs.enderchest.config.ApplicationProperties;
import pt.isep.desofs.enderchest.exception.security.InvalidFileTypeException;
import pt.isep.desofs.enderchest.exception.security.PathTraversalAttemptException;
// ... (outras importações)

@Service
public class FileStorageService {

    private final Path rootLocation;
    private final ApplicationProperties props;
    private final Tika tika = new Tika();

    // ... (construtor e método init)

    public void save(MultipartFile file) {
        // ... (validação de tamanho)

        try {
            // DEMONSTRAÇÃO DA MITIGAÇÃO T-06 (Web Shell)
            String detectedType = tika.detect(file.getInputStream());
            if (!props.storage().allowedMimeTypes().contains(detectedType)) {
                // Lançar a nossa exceção específica
                throw new InvalidFileTypeException(detectedType, String.join(", ", props.storage().allowedMimeTypes()));
            }
            
            // DEMONSTRAÇÃO DA MITIGAÇÃO T-05 (Path Traversal)
            String originalFilename = file.getOriginalFilename();
            if (originalFilename != null && (originalFilename.contains("..") || originalFilename.contains("/"))) {
                // Validação explícita do nome do ficheiro, mesmo que não o usemos para o path.
                // Isto é defesa em profundidade.
                throw new PathTraversalAttemptException();
            }

            // A vossa mitigação principal: Gerar um UUID. O código continua o mesmo...
            String filename = UUID.randomUUID().toString();
            Path destinationFile = this.rootLocation.resolve(filename).normalize().toAbsolutePath();

            if (!destinationFile.getParent().equals(this.rootLocation.toAbsolutePath())) {
                // Esta verificação é a vossa "última linha de defesa" contra path traversal.
                throw new PathTraversalAttemptException();
            }

            Files.copy(file.getInputStream(), destinationFile);

            // DEV_TEAM: Continuar com a lógica de negócio (cálculo de hash, persistência na BD)...

        } catch (IOException e) {
            throw new RuntimeException("Failed to store file.", e);
        }
    }
}