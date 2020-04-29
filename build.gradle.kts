plugins {
    `java-library`
    `maven-publish`
    signing
    jacoco
    id("me.champeau.gradle.jmh") version "0.5.0"
}

apply(from = "jdks.gradle.kts")

repositories {
    jcenter()
}

sourceSets {
    main {
        java {
            exclude("module-info.java")
        }
    }
    create("moduleInfo") {
        java {
            // We need the entire source directory here, otherwise we get a
            // "package is empty or does not exist" error during compilation.
            srcDir("src/main/java")
            compileClasspath = sourceSets.main.get().compileClasspath
        }
    }
}

dependencies {
    implementation("cafe.cryptography:curve25519-elisabeth:0.1.0")

    compileOnly("org.jetbrains:annotations:19.0.0")

    testImplementation("junit:junit:4.13") {
        exclude("org.hamcrest")
    }
    testImplementation("org.hamcrest:hamcrest:2.2")
    testImplementation("com.google.code.gson:gson:2.8.6")

    jmh("org.bouncycastle:bcprov-jdk15on:1.65")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

tasks.named<JavaCompile>("compileModuleInfoJava") {
    sourceCompatibility = "9"
    targetCompatibility = "9"

    doLast {
        // Leave only the module-info.class
        delete("$destinationDir/cafe")
    }
}

tasks.jar {
    // Add the Java 9+ module-info.class to the Java 7+ classes
    from(sourceSets["moduleInfo"].output)
}

group = "cafe.cryptography"
version = "0.1.0"
extra["isReleaseVersion"] = !version.toString().endsWith("SNAPSHOT")

tasks.register<Jar>("sourcesJar") {
    from(sourceSets.main.get().allJava)
    archiveClassifier.set("sources")
}

tasks.register<Jar>("javadocJar") {
    from(tasks.javadoc)
    archiveClassifier.set("javadoc")
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifact(tasks["sourcesJar"])
            artifact(tasks["javadocJar"])

            pom {
                name.set("ed25519-elisabeth")
                description.set("Pure Java implementation of the Ed25519 signature scheme")
                url.set("https://cryptography.cafe")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                developers {
                    developer {
                        id.set("str4d")
                        name.set("Jack Grigg")
                        email.set("thestr4d@gmail.com")
                    }
                }
                scm {
                    connection.set("scm:git:git://github.com/cryptography-cafe/ed25519-elisabeth.git")
                    developerConnection.set("scm:git:ssh://github.com:cryptography-cafe/ed25519-elisabeth.git")
                    url.set("https://github.com/cryptography-cafe/ed25519-elisabeth/tree/master")
                }
            }
        }
    }
    repositories {
        maven {
            val releasesRepoUrl = "https://oss.sonatype.org/service/local/staging/deploy/maven2/"
            val snapshotRepoUrl = "https://oss.sonatype.org/content/repositories/snapshots/"
            url = uri(if (version.toString().endsWith("SNAPSHOT")) snapshotRepoUrl else releasesRepoUrl)
            credentials {
                val NEXUS_USERNAME: String? by project
                val NEXUS_PASSWORD: String? by project
                username = NEXUS_USERNAME ?: ""
                password = NEXUS_PASSWORD ?: ""
            }
        }
    }
}

signing {
    setRequired({
        (project.extra["isReleaseVersion"] as Boolean) && gradle.taskGraph.hasTask("uploadArchives")
    })
    sign(publishing.publications["mavenJava"])
}

tasks.jacocoTestReport {
    reports {
        xml.isEnabled = true
        html.isEnabled = false
    }
}
tasks.check {
    dependsOn(tasks.jacocoTestReport)
}

apply(from = "javadoc.gradle.kts")
