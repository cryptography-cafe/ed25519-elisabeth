plugins {
    `java-library`
    `maven-publish`
    jacoco
    id("me.champeau.gradle.jmh") version "0.4.8"
}

repositories {
    jcenter()
    maven {
        url = uri("https://jitpack.io")
    }
}

dependencies {
    implementation("cafe.cryptography:curve25519-elisabeth:master-SNAPSHOT")

    testImplementation("junit:junit:4.12")
    testImplementation("org.hamcrest:hamcrest-all:1.3")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

group = "cafe.cryptography"
version = "0.0.0"

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
                val NEXUS_USERNAME: String by project
                val NEXUS_PASSWORD: String by project
                username = NEXUS_USERNAME
                password = NEXUS_PASSWORD
            }
        }
    }
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

// Set up bootstrapClasspath for Java 7.
val java7BootClasspath: String by project
val bootClasspath = if (hasProperty("java7BootClasspath")) java7BootClasspath else {
    var java7Home = System.getenv("JAVA7_HOME")
    if (java7Home != null) {
        "${java7Home}/jre/lib/jce.jar:${java7Home}/jre/lib/rt.jar"
    } else null
}
if (bootClasspath != null) {
    tasks.withType<JavaCompile>().configureEach {
        options.apply {
            bootstrapClasspath = files(bootClasspath)
        }
    }
}

// Set up Java override if configured (used to test with Java 7).
val javaHome: String by project
val targetJavaHome = if (hasProperty("javaHome")) javaHome else System.getenv("TARGET_JAVA_HOME")
if (targetJavaHome != null) {
    println("Target Java home set to ${targetJavaHome}")
    println("Configuring Gradle to use forked compilation and testing")

    val javaExecutablesPath = File(targetJavaHome, "bin")
    fun javaExecutable(execName: String): String {
        val executable = File(javaExecutablesPath, execName)
        require(executable.exists()) { "There is no ${execName} executable in ${javaExecutablesPath}" }
        return executable.toString()
    }

    tasks.withType<JavaCompile>().configureEach {
        options.apply {
            isFork = true
            forkOptions.javaHome = file(targetJavaHome)
        }
    }

    tasks.withType<Javadoc>().configureEach {
        executable = javaExecutable("javadoc")
    }

    tasks.withType<Test>().configureEach {
        executable = javaExecutable("java")
    }

    tasks.withType<JavaExec>().configureEach {
        executable = javaExecutable("java")
    }
}
