include(":certifikit")
include(":certifikit-cli")

dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven(url = "https://dl.bintray.com/kotlin/dokka")
        maven(url = "https://kotlin.bintray.com/kotlinx/")
        google()
    }
}