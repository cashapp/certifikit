package app.cash.certifikit

enum class KeyUsage(val bit: Int) {
  DigitalSignature(0),
  NonRepudiation(1),
  KeyEncipherment(2),
  DataEncipherment(3),
  KeyAgreement(4),
  KeyCertSign(5),
  CRLSign(6),
  EncipherOnly(7),
  DecipherOnly(8)
}

fun BitString.decodeKeyUsage(): List<KeyUsage> = bitSet.map { KeyUsage.values()[it] }
