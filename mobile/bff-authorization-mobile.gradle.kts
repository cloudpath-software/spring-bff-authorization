import java.util.Properties
import java.io.FileInputStream

plugins {
    kotlin("jvm")
    id("java-library")
    id("maven-publish")
}

java {
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("lib") {
            artifactId = "bff-authorization-mobile"

            from(components["java"])
        }
    }

    val nexusPropertiesFile = file("nexus.properties")
    var nexusUsername = ""
    var nexusPassword = ""

    if(nexusPropertiesFile.exists()) {
        val properties = Properties()
        properties.load(FileInputStream(nexusPropertiesFile))

        nexusUsername = properties.getProperty("username")
        nexusPassword = properties.getProperty("password")
    }

    repositories {
        mavenLocal()
        maven {
            isAllowInsecureProtocol = true
            url = uri("http://192.168.0.31:8282/repository/core-libraries/")
            credentials {
                username = nexusUsername
                password = nexusPassword
            }
        }
    }
}

dependencies {
    api(platform(project(":spring-bff-authorization-dependencies")))

    api("org.springframework.security:spring-security-config")
    api("org.springframework.security:spring-security-web")
    api("org.springframework.security:spring-security-oauth2-core")
    api("org.springframework.security:spring-security-oauth2-jose")
    api("org.springframework.security:spring-security-oauth2-resource-server")
    api("org.springframework:spring-core") {
        exclude(group = "commons-logging", module = "commons-logging")
    }
    api("com.nimbusds:nimbus-jose-jwt")
    api("com.fasterxml.jackson.core:jackson-databind")

    implementation("org.springframework.security:spring-security-oauth2-authorization-server:1.0.0")
//    implementation("org.springframework:spring-jdbc")

    implementation("org.springframework:spring-jdbc")

    implementation("com.google.api-client:google-api-client:2.1.1")

    api("jakarta.servlet:jakarta.servlet-api")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")

//    implementation("com.github.ben-manes:gradle-versions-plugin:0.25.0")
//    implementation("gradle.plugin.org.gretty:gretty:3.0.1")
    implementation("io.spring.gradle:dependency-management-plugin:1.0.15.RELEASE")
//    implementation("io.spring.gradle:docbook-reference-plugin:0.3.1")
//    implementation("io.spring.gradle:propdeps-plugin:0.0.10.RELEASE")
//    implementation("io.spring.javaformat:spring-javaformat-gradle-plugin:0.0.35")
//    implementation("io.spring.nohttp:nohttp-gradle:0.0.9")
//    implementation("org.asciidoctor:asciidoctor-gradle-jvm:3.1.0")
//    implementation("org.asciidoctor:asciidoctor-gradle-jvm-pdf:3.1.0")
//    implementation("org.hidetake:gradle-ssh-plugin:2.10.1") prevents gradle build
    implementation("org.sonarsource.scanner.gradle:sonarqube-gradle-plugin:3.3")

//
//    testImplementation("org.junit.jupiter:junit-jupiter-api:5.8.1")
//    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.8.1")
//    testImplementation("org.apache.commons:commons-io:1.3.2")
//    testImplementation("org.assertj:assertj-core:3.23.1")
//    testImplementation("org.mockito:mockito-core:3.0.0")
//    testImplementation("org.spockframework:spock-core:1.3-groovy-2.5")
//
//    testImplementation(kotlin("test"))
}