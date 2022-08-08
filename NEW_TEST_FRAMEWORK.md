# New test framework

Decision was made that new tests should be fully independent of existing [(old)](src/test) tests. It means that the new tests must:
* not use any of classes or resources located in [src/test/...](src/test),
* not use any of already declared test dependencies,
* be located in separate folder.

Thanks to that we can keep the possibility to execute the old tests, incrementally add new tests, and replace the old tests with new ones in the future.


## Project structure

Tests are located in two directories: 
* the source code of the existing tests is located in the [src/test/java](src/test/java) directory,
* the [src/newTest/java](src/newTest/java) directory contains the source code of tests implemented using the new test framework.

A new source set called `newTest` has been defined in [build.gradle](build.gradle), and configured:
* the production classes from the main source set are added to the compile time classpath,
* the production classes from the main source set are added to the runtime classpath,
* the source directory of new tests is set to `src/newTest/java`,
* the resource directory of new tests is set to `src/newTest/resources`.

## Dependencies

The Java Plugin automatically creates configurations for each of defined source sets.
Names of configurations are prefixed by the name of the source set, e.g. **newTest**RuntimeOnly, **newTest**CompileOnly.
`newTestImplementation` and `newTestRuntimeOnly` have been configured to extend from `implementation` and `runtimeOnly` respectively. 
As a result all the declared dependencies of the production code also become dependencies of the new tests.

## Running tests

There is a new task called `newTest` that runs new tests. It has been configured to run after the `test` task, e.g. when 
```
./gradlew clean build
```
command is executed. In order to run just the new test, use command:
```
./gradle clean newTest
```
