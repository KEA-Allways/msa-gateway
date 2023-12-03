FROM openjdk:11-jdk AS builder
COPY gradlew .
COPY gradle gradle
COPY build.gradle .
COPY settings.gradle .
COPY src src
RUN chmod +x ./gradlew
RUN ./gradlew bootJar
FROM openjdk:11-slim
COPY --from=builder build/libs/*.jar msa-gateway.jar
VOLUME /tmp
ENTRYPOINT ["java", "-jar", "-Dspring.profiles.active=prod", "-javaagent:/elastic-apm-agent-1.44.0.jar", "-Delastic.apm.service_name=msa-discovery", "-Delastic.apm.secret_token=hyUExzAkUlugz8LsPW", "-Delastic.apm.server_url=https://f694429f0917434384e0abfab751507d.apm.us-west-2.aws.cloud.es.io:443", "-Delastic.apm.environment=msa-discovery-environment", "-Delastic.apm.application_packages=com.allways", "msa-gateway.jar"]