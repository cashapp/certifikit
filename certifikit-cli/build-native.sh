#!/bin/sh

../gradlew assemble
mkdir build/graal
/Library/Java/JavaVirtualMachines/graalvm-ce-java11-20.1.0/Contents/Home/bin/native-image -jar ./build/install/certifikit-cli-shadow/lib/certifikit-cli-0.1.0-SNAPSHOT-all.jar --report-unsupported-elements-at-runtime --no-fallback --allow-incomplete-classpath -H:ReflectionConfigurationFiles=./build/resources/main/META-INF/native-image/app.cash.certifikit/certifikit-cli/reflect-config.json --enable-https build/graal/cft
