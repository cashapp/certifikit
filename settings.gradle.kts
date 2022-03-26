dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven(url = "https://dl.bintray.com/kotlin/dokka")
        maven(url = "https://kotlin.bintray.com/kotlinx/")
        google()
    }
}

// enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")
enableFeaturePreview("VERSION_CATALOGS")

include(":certifikit")
include(":certifikit-cli")
