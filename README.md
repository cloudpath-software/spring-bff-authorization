# Spring Backend for frontend authorization

The Spring Backend for frontend project is focused on delivering a simple and flexible abstraction for managing user sessions following 
a successful OAuth2 authorization. The source code is heavily inspired by the latest [Spring Authorization server](https://github.com/spring-projects/spring-authorization-server).

## Getting Started
The first place to start is to read the [Token Mediating and session Information Backend For Frontend](https://datatracker.ietf.org/doc/html/draft-bertocci-oauth2-tmi-bff-01)
and [OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-07) to gain an in-depth understanding on how to build an Authorization Server.

## Library development

This library is still in development, and probably will contain breaking changes in the future. It was built to resolve the issue of public clients not being issued
a refresh token by the [spring-authorization-server](https://github.com/spring-projects/spring-authorization-server). If there's interest, a release structure and issue tracking system
will be put in place.

Features to be considered

* Support mobile apps specific flows since using cookies isn't really convenient for android/ios apps.

## Recommendations for spa apps

Based on current best practices, it is not recommended to persist access/refresh tokens within the client
since it increases the surface of attacks and possibility of certain security vulnerabilities. For more info about this,
this [issue](https://github.com/spring-projects/spring-authorization-server/issues/297) discusses it in depth.

## Spring authorization server notes 

As specified by Joe Grandja, there are no plans to implement refresh tokens for public clients. Public clients are considered as not secured by nature of their uncontrolled environment.
This prevents them from being able to store client secrets securely. The authorization server explicitly will not generate a 
refresh token if the [client authentication method is none.](https://github.com/spring-projects/spring-authorization-server/blob/917988134765d297ec1be022d4fc3201c01c09fc/oauth2-authorization-server/src/main/java/org/springframework/security/oauth2/server/authorization/authentication/OAuth2AuthorizationCodeAuthenticationProvider.java#L189)

The recommendation is to use a [backend of frontend](https://samnewman.io/patterns/architectural/bff/) approach to manage user tokens and reduce the 
surface of attack by keeping client secrets & access tokens outside of public clients

### Building from Source
Spring Bff Authorization uses a [Gradle](https://gradle.org)-based build system.
In the instructions below, [`./gradlew`](https://vimeo.com/34436402) is invoked from the root of the source tree and serves as
a cross-platform, self-contained bootstrap mechanism for the build.

### Prerequisites
[Git](https://help.github.com/set-up-git-redirect) and the [JDK17 build](https://www.oracle.com/technetwork/java/javase/downloads).

Be sure that your `JAVA_HOME` environment variable points to the `jdk17` folder extracted from the JDK download.
 
### Check out sources
git clone git@github.com:Snapwise/spring-bff-authorization.git

## Contributing
[Pull requests](https://help.github.com/articles/creating-a-pull-request) are welcome. Contact me at [fabrizio.rodin-miron@snapwise.app](mailto:fabrizio.rodin-miron@snapwise.app?subject=[Github]%20Spring-bff-authorization)

## License
Spring Bff Authorization is Open Source software released under the
[Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.html).
