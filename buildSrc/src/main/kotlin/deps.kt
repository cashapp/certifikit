/*
  * Copyright (C) 2020 Square, Inc.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *    https://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */

object Versions {
    const val okio = "2.9.0"
    const val okhttp = "4.9.0"
    const val ktlintVersion = "0.34.2"
    const val kotlin = "1.4.30"
}

object Dependencies {
    const val assertj = "org.assertj:assertj-core:3.15.0"
    const val dokkaGradlePlugin = "org.jetbrains.dokka:dokka-gradle-plugin:0.10.1"
    const val junit5Api = "org.junit.jupiter:junit-jupiter-api:5.7.0"
    const val junit5JupiterEngine = "org.junit.jupiter:junit-jupiter-engine:5.7.0"
    const val junitGradlePlugin = "org.junit.platform:junit-platform-gradle-plugin:1.2.0"
    const val kotlinGradlePlugin = "org.jetbrains.kotlin:kotlin-gradle-plugin:${Versions.kotlin}"
    const val kotlinReflection = "org.jetbrains.kotlin:kotlin-reflect:${Versions.kotlin}"
    const val kotlinStdLib = "org.jetbrains.kotlin:kotlin-stdlib:${Versions.kotlin}"
    const val mavenPublishGradlePlugin = "com.vanniktech:gradle-maven-publish-plugin:0.11.1"
    const val okhttp = "com.squareup.okhttp3:okhttp:${Versions.okhttp}"
    const val okio = "com.squareup.okio:okio:${Versions.okio}"
    const val spotlessPlugin = "com.diffplug.spotless:spotless-plugin-gradle:5.6.1"
}