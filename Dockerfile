# =================================================================
# Dockerfile for Spring Boot Backend API
# =================================================================

# ---- Stage 1: Build the Application ----
# Use an official Maven image that includes Java 21 to compile our code.
# The 'AS build' part names this stage so we can reference it later.
FROM maven:3.9-eclipse-temurin-21 AS build

# Set the working directory inside the container. All subsequent commands
# will run from this directory.
WORKDIR /app

# Copy the Maven project file first. Docker caches layers, so this speeds up
# subsequent builds if only the source code changes.
COPY pom.xml .

# Copy the Maven wrapper files, which are used by the build command.
COPY .mvn/ .mvn
COPY mvnw .
COPY mvnw.cmd .

# Copy the rest of the application's source code into the container.
COPY src ./src

# Run the Maven build command. This compiles the Java code, runs tests (which we skip
# for faster deployment), and packages the application into an executable JAR file.
RUN mvn clean install -DskipTests


# ---- Stage 2: Create the Final, Lightweight Image ----
# Use a slim, official OpenJDK image. This image only contains the Java Runtime
# Environment, making our final container much smaller and more secure than the
# full Maven image.
FROM openjdk:21-jdk-slim

# Set the working directory inside the final container.
WORKDIR /app

# Copy ONLY the compiled JAR file from the 'build' stage into this final image.
# This is the key to creating a small, efficient production image.
# !! ACTION REQUIRED: Make sure 'gemini-0.0.1-SNAPSHOT.jar' matches your pom.xml !!
COPY --from=build /app/target/gemini-0.0.1-SNAPSHOT.jar app.jar

# Expose the port that the Spring Boot application will run on.
# Cloud platforms like Railway will automatically detect and use this port.
EXPOSE 8080

# This is the command that will be executed when the container starts.
# It simply runs the Java application from the JAR file.
ENTRYPOINT ["java", "-jar", "app.jar"]