plugins {
    id("java-platform")
    id("maven-publish")
}

javaPlatform {
    allowDependencies()
}

publishing {
    publications {
        create<MavenPublication>("lib") {
            artifactId = "spring-bff-authorization-dependencies"
            from(components["javaPlatform"])
        }
    }

    val nexusPropertiesFile = file("../nexus.properties")
    var nexusUsername = ""
    var nexusPassword = ""

    if(nexusPropertiesFile.exists()) {
        val properties = java.util.Properties()
        properties.load(java.io.FileInputStream(nexusPropertiesFile))

        nexusUsername = properties.getProperty("username")
        nexusPassword = properties.getProperty("password")
    }

    repositories {
        mavenLocal()
        maven {
            isAllowInsecureProtocol = true
            url = uri("http://192.168.0.31:8282/repository/maven-releases/")
            credentials {
                username = nexusUsername
                password = nexusPassword
            }
        }
    }
}

dependencies {
    api(platform("org.springframework:spring-framework-bom:${project.properties["springFrameworkVersion"]}"))
    api(platform("org.springframework.security:spring-security-bom:${project.properties["springSecurityVersion"]}"))
    api(platform("com.fasterxml.jackson:jackson-bom:2.14.0"))
    constraints {
        api("com.nimbusds:nimbus-jose-jwt:9.24.4")
        api("jakarta.servlet:jakarta.servlet-api:6.0.0")
        api("org.slf4j:slf4j-api:2.0.6")
        api("org.junit.jupiter:junit-jupiter:5.9.1")
        api("org.assertj:assertj-core:3.23.1")
        api("org.mockito:mockito-core:4.8.1")
        api("com.squareup.okhttp3:mockwebserver:4.10.0")
        api("com.squareup.okhttp3:okhttp:4.10.0")
        api("com.jayway.jsonpath:json-path:2.7.0")
        api("org.hsqldb:hsqldb:2.7.1")
    }
}