# ---- Build Stage ----
# Use a Maven image to build the project JAR file
FROM maven:3.8.5-openjdk-17 AS build

# Set the working directory
WORKDIR /app

# Copy the pom.xml file first to leverage Docker layer caching
COPY pom.xml .

# Copy the rest of the project source code
COPY src ./src

# Run the Maven build command to create the executable JAR
# The "-DskipTests" flag speeds up the build process for deployment
RUN mvn clean package -DskipTests

# ---- Run Stage ----
# Use a lightweight Java image to run the application
FROM openjdk:17-jdk-slim

# Set the working directory
WORKDIR /app

# Copy the built JAR file from the 'build' stage
# Make sure 'resumescreener-0.0.1-SNAPSHOT.jar' matches your pom.xml <artifactId> and <version>
COPY --from=build /app/target/resumescreener-0.0.1-SNAPSHOT.jar app.jar

# Expose the port the application will run on
# Render will map its internal port to this one
EXPOSE 8080

# The command to run the application
ENTRYPOINT ["java", "-jar", "app.jar"]