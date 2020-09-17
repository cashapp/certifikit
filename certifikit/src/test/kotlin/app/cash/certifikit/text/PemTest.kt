package app.cash.certifikit.text

import org.junit.Test
import java.io.File
import org.assertj.core.api.Assertions.assertThat

class PemTest {
  @Test
  fun parseHeldCertificate() {
    val (pkcs8pair, cert1) = decode(File("src/test/resources/pkcs8pair.pem").readText())
    val (pkcs1pair, cert2) = decode(File("src/test/resources/pkcs1pair.pem").readText())

    assertThat(cert1).isEqualTo(cert2)
    assertThat(pkcs1pair.private).isEqualTo(pkcs8pair.private)
    assertThat(pkcs1pair.public).isEqualTo(pkcs8pair.public)
  }
}