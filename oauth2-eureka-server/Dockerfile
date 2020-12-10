FROM openjdk:8-jdk-alpine

ARG JAR_FILE=target/*.jar

RUN mkdir /app/

COPY ${JAR_FILE} /app/app.jar

RUN echo "java \$JAVA_OPTS -jar /app/app.jar" > /start.sh

RUN chmod +x /start.sh


ENTRYPOINT ["/start.sh"]