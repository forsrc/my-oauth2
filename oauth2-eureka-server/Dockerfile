FROM maven:3.6.3-jdk-8 as builder

COPY . /app

WORKDIR /app
RUN mvn -B package

FROM openjdk:8-jdk-alpine

RUN mkdir /app/

WORKDIR /app

#ARG JAR_FILE=target/*.jar
#COPY ${JAR_FILE} /app/app.jar

COPY --from=builder /app/target/*.jar /app/

RUN echo "exec java \$JAVA_OPTS -jar /app/app.jar" > /start.sh

RUN chmod +x /start.sh


ENTRYPOINT ["/start.sh"]