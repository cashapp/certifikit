package app.cash.certifikit.cli

import java.io.File
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

fun File.trustManager(): X509TrustManager {
    val factory = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm())

    val keyStore = KeyStore.getInstance(this, null as? CharArray)
    factory.init(keyStore)

    val trustManagers = factory.trustManagers!!
    check(trustManagers.size == 1 && trustManagers[0] is X509TrustManager) {
        "Unexpected default trust managers: ${trustManagers.contentToString()}"
    }
    return trustManagers[0] as X509TrustManager
}