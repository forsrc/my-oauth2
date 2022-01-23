FROM maven:3.8.4-openjdk-8 as builder

COPY . /app

WORKDIR /app
RUN mvn -B package -DskipTests

FROM openjdk:8-jdk

RUN mkdir /app/

WORKDIR /app

ARG JAR_FILE=target/*.jar
ARG APP_PORT=80

#COPY ${JAR_FILE} /app/app.jar

COPY --from=builder /app/target/*.jar /app/app.jar
RUN chmod +x /app/app.jar

EXPOSE $APP_PORT

ENTRYPOINT ["/bin/sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]