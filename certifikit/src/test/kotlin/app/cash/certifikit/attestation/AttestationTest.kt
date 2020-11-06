/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package okhttp3.tls.internal.der

import app.cash.certifikit.CertificateAdapters
import app.cash.certifikit.attestation.AttestationAdapters
import app.cash.certifikit.attestation.AuthorizationList
import app.cash.certifikit.attestation.KeyDescription
import app.cash.certifikit.attestation.RootOfTrust
import app.cash.certifikit.decodeCertificatePem
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class AttestTest {
  @Test
  fun `decode attestation certificate`() {
    // https://github.com/google/android-key-attestation/blob/master/server/examples/pem/algorithm_EC_SecurityLevel_StrongBox/cert0.pem
    val certificateBase64 = """
        |MIID8zCCA5egAwIBAgIBATAMBggqhkjOPQQDAgUAMC8xGTAXBgNVBAUTEDY5N2JjNjRiNmNkNGMw
        |MWUxEjAQBgNVBAwMCVN0cm9uZ0JveDAeFw03MDAxMDEwMDAwMDBaFw0yODA1MjMyMzU5NTlaMB8x
        |HTAbBgNVBAMMFEFuZHJvaWQgS2V5c3RvcmUgS2V5MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        |M8o810z1VgBTtio2H1Gh5vA3ySYQ0/RIfn/uPQRCiHGZ1K7tvhQobsfa04rM5PAPuaZDmDnD86C5
        |T9SL+msTVqOCArAwggKsMA4GA1UdDwEB/wQEAwIHgDCCApgGCisGAQQB1nkCAREEggKIMIIChAIB
        |AwoBAgIBBAoBAgQDYWJjBAAwggHNv4U9CAIGAWvSW/8Tv4VFggG7BIIBtzCCAbMxggGLMAwEB2Fu
        |ZHJvaWQCAR0wGQQUY29tLmFuZHJvaWQua2V5Y2hhaW4CAR0wGQQUY29tLmFuZHJvaWQuc2V0dGlu
        |Z3MCAR0wGQQUY29tLnF0aS5kaWFnc2VydmljZXMCAR0wGgQVY29tLmFuZHJvaWQuZHluc3lzdGVt
        |AgEdMB0EGGNvbS5hbmRyb2lkLmlucHV0ZGV2aWNlcwIBHTAfBBpjb20uYW5kcm9pZC5sb2NhbHRy
        |YW5zcG9ydAIBHTAfBBpjb20uYW5kcm9pZC5sb2NhdGlvbi5mdXNlZAIBHTAfBBpjb20uYW5kcm9p
        |ZC5zZXJ2ZXIudGVsZWNvbQIBHTAgBBtjb20uYW5kcm9pZC53YWxscGFwZXJiYWNrdXACAR0wIQQc
        |Y29tLmdvb2dsZS5TU1Jlc3RhcnREZXRlY3RvcgIBHTAiBB1jb20uZ29vZ2xlLmFuZHJvaWQuaGlk
        |ZGVubWVudQIBATAjBB5jb20uYW5kcm9pZC5wcm92aWRlcnMuc2V0dGluZ3MCAR0xIgQgMBqjywgR
        |NFAcRfFCKrxmwkIk/V3tX9yPF+aXF2/YZqowgZ2hCDEGAgECAgEDogMCAQOjBAICAQClBTEDAgEE
        |v4N3AgUAv4U+AwIBAL+FQEwwSgQgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQAK
        |AQIEIHKNsSdPHxzxVx3kOAsEilVKxKOA529TVQg1KQhKk3gBv4VBAwIBAL+FQgUCAwMUs7+FTgYC
        |BAE0FfG/hU8GAgQBNBXsMAwGCCqGSM49BAMCBQADSAAwRQIhAN82bz9RzrMXznZKgu61ktdu397w
        |VvW2Fj/ZKOkcy8p/AiAFhziu1TGVBklOdPH4usrPM/FxAvlOSUDQwj4HP/9PSg==
        |""".trimMargin()
    val certificateByteString = certificateBase64.decodeBase64()!!
    val certificatePem = """
        |-----BEGIN CERTIFICATE-----
        |$certificateBase64
        |-----END CERTIFICATE-----
        |""".trimMargin()

    val javaCertificate = certificatePem.decodeCertificatePem()
    val okHttpCertificate = CertificateAdapters.certificate
        .fromDer(certificateByteString)

    assertThat(okHttpCertificate.signatureValue.byteString)
        .isEqualTo(javaCertificate.signature.toByteString())

    val keyDescription = okHttpCertificate.tbsCertificate.extensions.first {
      it.id == AttestationAdapters.KEY_DESCRIPTION_OID
    }.value as KeyDescription

    assertThat(keyDescription).isEqualTo(
        KeyDescription(
            attestationVersion = 3L,
            attestationSecurityLevel = 2L, // 2=StrongBox
            keymasterVersion = 4L,
            keymasterSecurityLevel = 2L, // 2=StrongBox
            attestationChallenge = "abc".encodeUtf8(),
            uniqueId = ByteString.EMPTY,
            softwareEnforced = AuthorizationList(
                creationDateTime = 1562602372883L,
                attestationApplicationId = "308201b33182018b300c0407616e64726f696402011d30190414636f6d2e616e64726f69642e6b6579636861696e02011d30190414636f6d2e616e64726f69642e73657474696e677302011d30190414636f6d2e7174692e64696167736572766963657302011d301a0415636f6d2e616e64726f69642e64796e73797374656d02011d301d0418636f6d2e616e64726f69642e696e7075746465766963657302011d301f041a636f6d2e616e64726f69642e6c6f63616c7472616e73706f727402011d301f041a636f6d2e616e64726f69642e6c6f636174696f6e2e667573656402011d301f041a636f6d2e616e64726f69642e7365727665722e74656c65636f6d02011d3020041b636f6d2e616e64726f69642e77616c6c70617065726261636b757002011d3021041c636f6d2e676f6f676c652e5353526573746172744465746563746f7202011d3022041d636f6d2e676f6f676c652e616e64726f69642e68696464656e6d656e750201013023041e636f6d2e616e64726f69642e70726f7669646572732e73657474696e677302011d31220420301aa3cb081134501c45f1422abc66c24224fd5ded5fdc8f17e697176fd866aa".decodeHex()
            ),
            teeEnforced = AuthorizationList(
                purpose = listOf(2L, 3L),
                algorithm = 3L,
                keySize = 256L,
                digest = listOf(4L),
                origin = 0,
                rootOfTrust = RootOfTrust(
                    verifiedBootKey = "0000000000000000000000000000000000000000000000000000000000000000".decodeHex(),
                    deviceLocked = false,
                    verifiedBootState = 2L,
                    verifiedBootHash = "728db1274f1f1cf1571de4380b048a554ac4a380e76f5355083529084a937801".decodeHex()
                ),
                osVersion = 0L,
                osPatchLevel = 201907L,
                vendorPatchLevel = 20190705L,
                bootPatchLevel = 20190700L
            )
        )
    )
  }
}
