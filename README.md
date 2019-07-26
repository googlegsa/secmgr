Building the Google GSA Security Manager
----------------------------------------

Building the Google GSA Security Manager requires the following development tools:
  Java SE Development Kit (JDK) version 1.8 or greater
  (Optional) Apache Maven version 3.3.0 or greater

Maven commands:
  mvn install - download required dependencies, build and install into local maven repository
  mvn clean   - deletes all compiled and generated files
  mvn compile - compiles source
  mvn test    - runs tests
  mvn package - compiles, tests, and creates the jar files and distribution packages

Using the multi-platform Maven Wrapper:
 If you do not have Maven installed, you can use the included Maven wrapper scripts instead:

 './mvnw <target>' (on Unix / Linux / Mac) or 'mvnw.cmd <target>' (on Windows).

 This will download a specific version of Maven and run that instead of your system-wide
 installed version. Use any of the Maven commands listed above as <target>.
