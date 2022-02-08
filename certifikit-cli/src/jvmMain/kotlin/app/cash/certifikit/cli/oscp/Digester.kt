/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License, version
 * 2.0 (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package app.cash.certifikit.cli.oscp

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.io.DigestOutputStream
import org.bouncycastle.operator.DigestCalculator
import java.io.OutputStream

/**
 * BC's [OCSPReqBuilder] needs a [DigestCalculator] but BC doesn't
 * provide any public implementations of that interface. That's why we need to
 * write our own. There's a default SHA-1 implementation and one for SHA-256.
 * Which one to use will depend on the Certificate Authority (CA).
 */
class Digester(digest: Digest, private val algId: AlgorithmIdentifier) :
  DigestCalculator {
  private val dos: DigestOutputStream = DigestOutputStream(digest)
  override fun getAlgorithmIdentifier(): AlgorithmIdentifier {
    return algId
  }

  override fun getOutputStream(): OutputStream {
    return dos
  }

  override fun getDigest(): ByteArray {
    return dos.digest
  }

  companion object {
    fun sha1(): DigestCalculator {
      val digest: Digest = SHA1Digest()
      val algId = AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1)
      return Digester(digest, algId)
    }

    fun sha256(): DigestCalculator {
      val digest: Digest = SHA256Digest()
      // The OID for SHA-256: http://www.oid-info.com/get/2.16.840.1.101.3.4.2.1
      val oid = ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1").intern()
      val algId = AlgorithmIdentifier(oid)
      return Digester(digest, algId)
    }
  }
}
