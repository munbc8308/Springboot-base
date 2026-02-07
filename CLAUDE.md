# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
./gradlew build          # Build the project
./gradlew bootRun        # Run the application (default: http://localhost:8080)
./gradlew test           # Run all tests
./gradlew test --tests "com.spring.lica.SomeTest.someMethod"  # Run a single test
```

- **Java 21** required (configured via Gradle toolchain)
- **Gradle 8.14.4** (use wrapper `./gradlew`, not system Gradle)

## Architecture

This is a **modular Spring Boot 3.5.0 template** project. All optional features are excluded from auto-configuration in `LicaApplication.java` and selectively re-enabled via per-module `@Configuration` classes that use `@ConditionalOnProperty`.

### Module Toggle System

Every optional module is controlled by a property flag in `application.properties`:

```
app.module.<name>.enabled=true|false
```

Each module has a corresponding config class in `com.spring.lica.config` (e.g., `KafkaConfig`, `RedisConfig`, `FlywayConfig`) that imports the excluded Spring Boot auto-configuration only when its flag is `true`. When adding a new module, follow this pattern: exclude its auto-configuration in `LicaApplication.java`, create a config class with `@ConditionalOnProperty`, and add the toggle property.

**Enabled by default**: JDBC, JPA, Thymeleaf, DevTools
**Disabled by default**: QueryDSL, Actuator, OpenAPI, Flyway, Mail, AOP, WebSocket, OAuth2, GraphQL, Config Reload, P6Spy, Redis, Kafka, RabbitMQ

### Two-Tier Security

Security is split into two independent filter chains in order of priority:

1. **Admin UI** (`@Order(1)` in `admin/AdminSecurityConfig.java`) — Session-based form login for `/admin/**` paths, requires `ROLE_ADMIN`
2. **API** (`@Order(2)` in `config/SecurityConfig.java`) — Stateless JWT authentication for all other paths. Public: `/h2-console/**`, `/api/auth/**`

JWT implementation lives in `security/jwt/` with `JwtTokenProvider` (token create/validate) and `JwtAuthenticationFilter` (extracts Bearer token from Authorization header).

### Key Packages

- `com.spring.lica.config` — Module configuration classes (one per feature)
- `com.spring.lica.security.jwt` — JWT token provider, filter, and properties
- `com.spring.lica.admin` — Admin UI controller, settings service, and security config
- `com.spring.lica.messaging.kafka` — Kafka producer/consumer services
- `com.spring.lica.messaging.rabbitmq` — RabbitMQ producer/consumer services

### Admin Settings UI

The admin panel (`/admin/settings`) reads and writes `application.properties` at runtime via `SettingsService`. It uses Thymeleaf templates in `resources/templates/` and parses property file comments (`#` lines) as section headers.

## Database

H2 in-memory database (`jdbc:h2:mem:licadb`). Console at `/h2-console` (user: `sa`, no password). JPA uses `ddl-auto=create-drop`.

## Logging

Configured in `logback-spring.xml`. Profile-based: `local`/`dev`/`default` profiles log to console only; `prod` profile adds file rotation (100MB/file, 30-day retention).
