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

import app.cash.certifikit.Certificate
import app.cash.certifikit.CertificateAdapters
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import java.math.BigInteger
import java.security.SecureRandom

fun SecureRandom.nextBytes(count: Int) = ByteArray(count).apply {
  nextBytes(this)
}

// https://github.com/netty/netty/blob/bd8cea644a07890f5bada18ddff0a849b58cd861/example/src/main/java/io/netty/example/ocsp/OcspRequestBuilder.java
class OscpClient(val httpClient: OkHttpClient) {
  val random = SecureRandom()

  /**
   * ATTENTION: The returned [OCSPReq] is not re-usable/cacheable! It contains a one-time nonce
   * and CA's will (should) reject subsequent requests that have the same nonce value.
   */
  fun request(certificate: Certificate, issuer: Certificate): OCSPReq {
    val serial: BigInteger = certificate.tbsCertificate.serialNumber
    val issuerBytes = CertificateAdapters.certificate.toDer(issuer)
    val certId =
        CertificateID(Digester.sha1(), X509CertificateHolder(issuerBytes.toByteArray()), serial)

    val builder = OCSPReqBuilder()
    builder.addRequest(certId)

    val extensions: Array<Extension> =
        arrayOf(Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
            DEROctetString(random.nextBytes(8))))
    builder.setRequestExtensions(Extensions(extensions))

    return builder.build()
  }

  fun submit(certificate: Certificate, request: OCSPReq): OCSPResp {
    val httpRequest = Request.Builder().url("").build()
    val call = httpClient.newCall(httpRequest)

    val response = call.execute()
  }
}