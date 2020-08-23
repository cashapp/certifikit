package app.cash.certifikit.cli

import java.io.File
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class TestCerts {
  @Test
  fun parseCert() {
      val cert = File("src/test/resources/cert.pem").readText().parsePemCertificate()
      assertThat(cert.signatureAlgorithm.algorithm).isEqualTo("1.2.840.113549.1.1.11")
  }
}
