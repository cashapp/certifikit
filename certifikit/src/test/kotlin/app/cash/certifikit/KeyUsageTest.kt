package app.cash.certifikit

import app.cash.certifikit.KeyUsage.CRLSign
import app.cash.certifikit.KeyUsage.DigitalSignature
import app.cash.certifikit.KeyUsage.KeyCertSign
import okio.ByteString.Companion.decodeHex
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class KeyUsageTest {
  @Test
  fun testKnownValues() {
    assertThat(BitString("80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage()).containsExactly(
        DigitalSignature)
    assertThat(BitString("06".decodeHex(), unusedBitsCount = 1).decodeKeyUsage()).containsExactly(
        KeyCertSign, CRLSign)
    assertThat(BitString("86".decodeHex(), unusedBitsCount = 1).decodeKeyUsage()).containsExactly(
        DigitalSignature, KeyCertSign, CRLSign)
  }

  @Test
  fun testEdgeValues() {
    assertThat(BitString("".decodeHex(), unusedBitsCount = 0).decodeKeyUsage()).isEmpty()
    assertThat(BitString("FF80".decodeHex(), unusedBitsCount = 7).decodeKeyUsage()).containsExactly(
        *KeyUsage.values())
  }
}
