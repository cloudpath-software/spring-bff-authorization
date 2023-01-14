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
    api(platform("org.springframework.cloud:spring-cloud-dependencies:${project.properties["springCloudVersion"]}"))
    implementation(project(":bff-authorization-core"))
    implementation("org.springframework.cloud:spring-cloud-starter-gateway")
}