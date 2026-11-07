plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "org.moonnaive.plugin"

    // Unsigned release by default. Signing belongs to the downstream owner.
    buildTypes {
        getByName("release") { isMinifyEnabled = true }
    }

    buildToolsVersion = "36.0.0"

    compileSdk = 36

    defaultConfig {
        minSdk = 24
        targetSdk = 36

        applicationId = "org.moonnaive.plugin"
        versionCode = 1
        versionName = "0.1.0"
        splits.abi {
            isEnable = true
            isUniversalApk = false
            reset()
            include(System.getenv("APK_ABI") ?: "arm64-v8a")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    lint {
        showAll = true
        checkAllWarnings = true
        checkReleaseBuilds = false
        warningsAsErrors = true
    }

    packaging {
        jniLibs.useLegacyPackaging = true
    }

    applicationVariants.all {
        outputs.all {
            this as com.android.build.gradle.internal.api.BaseVariantOutputImpl
            outputFileName =
                outputFileName.replace(project.name, "moon-naive-plugin-v$versionName")
                    .replace("-release", "")
                    .replace("-oss", "")
        }
    }

    sourceSets.getByName("main") {
        jniLibs.srcDir("libs")
    }
}

// Never produce an apparently installable plugin with no executable inside.
tasks.named("preBuild") {
    doFirst {
        val abi = System.getenv("APK_ABI") ?: "arm64-v8a"
        require(abi in setOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64"))
        val executable = file("libs/$abi/libnaive.so")
        require(executable.isFile && executable.length() > 0) {
            "Build the patched Android client first: missing $executable"
        }
    }
}
