package pt.isep.desofs.enderchest.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.util.unit.DataSize;
import java.util.Set;

@ConfigurationProperties(prefix = "enderchest")
public record ApplicationProperties(Storage storage, RateLimit rateLimit) {
    
    public record Storage(String basePath, String maxFileSize, Set<String> allowedMimeTypes, String storageQuota) {
        
        // Método auxiliar para converter a string "10MB" em bytes reais
        public long maxFileSizeInBytes() {
            return DataSize.parse(maxFileSize != null ? maxFileSize : "0B").toBytes();
        }
        
        // Método auxiliar para converter a string "1GB" em bytes reais (storage quota)
        public long storageQuotaInBytes() {
            return DataSize.parse(storageQuota != null ? storageQuota : "1GB").toBytes();
        }
    }
    
    public record RateLimit(int requestsPerWindow, int windowSeconds) {
        // Rate limiting configuration: requestsPerWindow requests per windowSeconds
        // Defaults: 100 requests per 60 seconds
        public RateLimit {
            if (requestsPerWindow <= 0) {
                requestsPerWindow = 100;
            }
            if (windowSeconds <= 0) {
                windowSeconds = 60;
            }
        }
    }
}