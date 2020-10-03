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

import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.ObjectIdentifiers
import app.cash.certifikit.cli.execute
import java.io.IOException
import java.lang.IllegalArgumentException
import java.lang.IllegalStateException
import java.math.BigInteger
import java.security.SecureRandom
import java.security.cert.X509Certificate
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.ByteString.Companion.toByteString
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.OCSPReq
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp

fun X509Certificate.toCertificate() =
    CertificateAdapters.certificate.fromDer(encoded.toByteString())

fun SecureRandom.nextBytes(count: Int) = ByteArray(count).apply {
  nextBytes(this)
}

// https://github.com/netty/netty/blob/bd8cea644a07890f5bada18ddff0a849b58cd861/example/src/main/java/io/netty/example/ocsp/OcspRequestBuilder.java
// https://raymii.org/s/articles/OpenSSL_Manually_Verify_a_certificate_against_an_OCSP.html
class OscpClient(val httpClient: OkHttpClient) {
  val random = SecureRandom()

  /**
   * ATTENTION: The returned [OCSPReq] is not re-usable/cacheable! It contains a one-time nonce
   * and CA's will (should) reject subsequent requests that have the same nonce value.
   */
  fun request(certificateX: X509Certificate, issuerX: X509Certificate): OCSPReq {
    val serial: BigInteger = certificateX.serialNumber
    val certId =
        CertificateID(Digester.sha1(), X509CertificateHolder(issuerX.encoded), serial)

    val builder = OCSPReqBuilder()
    builder.addRequest(certId)

    val extensions: Array<Extension> =
        arrayOf(Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false,
            DEROctetString(random.nextBytes(8))))
    builder.setRequestExtensions(Extensions(extensions))

    return builder.build()
  }

  suspend fun submit(certificateX: X509Certificate, issuerCertificateX: X509Certificate): OcspResponse? {
    val certificate = certificateX.toCertificate()

    val accessLocation =
        certificate.authorityInfoAccess?.find { it.accessMethod == ObjectIdentifiers.ocsp }?.accessLocation?.second
            ?: return null

    val url = accessLocation.toString().toHttpUrlOrNull() ?: throw IllegalArgumentException(
        "Unable to parse OCSP url $accessLocation")

    val request = request(certificateX, issuerCertificateX)

    val secureUrl = url.newBuilder().scheme("https").build()

    val httpRequest = Request.Builder()
        .url(secureUrl)
        .header("accept", "application/ocsp-response")
        .post(request.encoded.toRequestBody(contentType = "application/ocsp-request".toMediaType()))
        .build()

    val response = try {
      httpClient.execute(httpRequest)
    } catch (e: IOException) {
      return OcspResponse(failure = e, url = secureUrl)
    }

    val bytes = withContext(Dispatchers.IO) { response.body?.bytes() }
    val ocspResponse = OCSPResp(bytes)

    val requestStatus =
        Status.values().find { it.code == ocspResponse.status } ?: throw IllegalStateException(
            "Unknown response: " + ocspResponse.status)

    val responseObject = ocspResponse.responseObject as BasicOCSPResp

    return OcspResponse(requestStatus, responseObject, url)
  }
}
