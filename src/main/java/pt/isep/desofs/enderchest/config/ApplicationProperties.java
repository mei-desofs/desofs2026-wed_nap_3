package pt.isep.desofs.enderchest.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;
import java.util.Set;

@ConfigurationProperties(prefix = "enderchest")
public record ApplicationProperties(Storage storage) {
    
    public record Storage(String basePath, String maxFileSize, Set<String> allowedMimeTypes) {
        
        // Método auxiliar para converter a string "10MB" em bytes reais
        public long maxFileSizeInBytes() {
            return DataSize.parse(maxFileSize != null ? maxFileSize : "0B").toBytes();
        }
    }
}