## Call-Sequence Pass

## Compilation

### The Following Environment Variable must be set:
```
ANDROID_HOME=<filepath to platforms>
```
* note that the `platforms` folder is provided and located in current directory.

We use Maven to compile the call-sequence pass into jar. To install Maven: https://maven.apache.org/install.html.

Specifically, we use Maven version 3.8.6.

Assumed we are in current directory:
```
mvn clean install
```

The compiled jar `callseq-1.0-jar-with-dependencies.jar` is placed in the target folder.

__NOTE__: We also provide a pre-compiled `callseq-1.0-jar-with-dependencies.jar`, which you can find in current directory.

## Runing the Call-Sequence Pass

```
java -cp callseq-1.0-jar-with-dependencies.jar aaa.bbb.ccc.path.analyses.AndrolibDriver -j <filepath to app>
```

To additionally enable callback analysis:
```
java -cp callseq-1.0-jar-with-dependencies.jar aaa.bbb.ccc.path.analyses.AndrolibDriver --callback -j <filepath to app>
```

* the following folder must exist in current directory: `nativeAnalysis`.
* for Java, we use [Amazon Corretto 8](https://docs.aws.amazon.com/corretto/latest/corretto-8-ug/downloads-list.html).

### Outputs

The json files for the call sequences are produced in `nativeAnalysis`.
