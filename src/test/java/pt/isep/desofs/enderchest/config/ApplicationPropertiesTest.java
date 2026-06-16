package pt.isep.desofs.enderchest.config;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("ApplicationProperties Unit Tests")
class ApplicationPropertiesTest {

    @Test
    @DisplayName("Storage: maxFileSizeInBytes parses human-readable size")
    void storage_maxFileSizeInBytes() {
        ApplicationProperties.Storage storage =
                new ApplicationProperties.Storage("/tmp", "10MB", Set.of("image/png"), "1GB");
        assertEquals(10L * 1024 * 1024, storage.maxFileSizeInBytes());
    }

    @Test
    @DisplayName("Storage: maxFileSizeInBytes defaults to 0 when null")
    void storage_maxFileSizeInBytes_null() {
        ApplicationProperties.Storage storage =
                new ApplicationProperties.Storage("/tmp", null, Set.of(), null);
        assertEquals(0L, storage.maxFileSizeInBytes());
    }

    @Test
    @DisplayName("Storage: storageQuotaInBytes parses configured quota")
    void storage_storageQuotaInBytes() {
        ApplicationProperties.Storage storage =
                new ApplicationProperties.Storage("/tmp", "10MB", Set.of(), "2GB");
        assertEquals(2L * 1024 * 1024 * 1024, storage.storageQuotaInBytes());
    }

    @Test
    @DisplayName("Storage: storageQuotaInBytes defaults to 1GB when null")
    void storage_storageQuotaInBytes_null() {
        ApplicationProperties.Storage storage =
                new ApplicationProperties.Storage("/tmp", "10MB", Set.of(), null);
        assertEquals(1L * 1024 * 1024 * 1024, storage.storageQuotaInBytes());
    }

    @Test
    @DisplayName("RateLimit: keeps valid configured values")
    void rateLimit_validValues() {
        ApplicationProperties.RateLimit rateLimit = new ApplicationProperties.RateLimit(50, 30);
        assertEquals(50, rateLimit.requestsPerWindow());
        assertEquals(30, rateLimit.windowSeconds());
    }

    @Test
    @DisplayName("RateLimit: applies defaults when values are non-positive")
    void rateLimit_defaults() {
        ApplicationProperties.RateLimit rateLimit = new ApplicationProperties.RateLimit(0, -5);
        assertEquals(100, rateLimit.requestsPerWindow());
        assertEquals(60, rateLimit.windowSeconds());
    }

    @Test
    @DisplayName("Record accessors expose storage and rateLimit")
    void record_accessors() {
        ApplicationProperties.Storage storage =
                new ApplicationProperties.Storage("/data", "5MB", Set.of("text/plain"), "500MB");
        ApplicationProperties.RateLimit rateLimit = new ApplicationProperties.RateLimit(10, 10);
        ApplicationProperties props = new ApplicationProperties(storage, rateLimit);

        assertSame(storage, props.storage());
        assertSame(rateLimit, props.rateLimit());
        assertEquals("/data", props.storage().basePath());
        assertTrue(props.storage().allowedMimeTypes().contains("text/plain"));
    }
}
