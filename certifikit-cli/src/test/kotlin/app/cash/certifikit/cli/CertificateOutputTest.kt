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
package app.cash.certifikit.cli

import app.cash.certifikit.CertificateAdapters
import okio.ByteString.Companion.decodeBase64
import org.assertj.core.api.Assertions.assertThat
import org.junit.Test

class CertificateOutputTest {
  val certificateBase64 = """
        |MIIHHTCCBgWgAwIBAgIRAL5oALmpH7l6AAAAAFTRMh0wDQYJKoZIhvcNAQELBQAw
        |gboxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQL
        |Ex9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykg
        |MjAxNCBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxLjAs
        |BgNVBAMTJUVudHJ1c3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBMMU0wHhcN
        |MjAwNDEzMTMyNTQ5WhcNMjEwNDEyMTM1NTQ5WjCBxTELMAkGA1UEBhMCVVMxEzAR
        |BgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgsr
        |BgEEAYI3PAIBAxMCVVMxGTAXBgsrBgEEAYI3PAIBAhMIRGVsYXdhcmUxFTATBgNV
        |BAoTDFNxdWFyZSwgSW5jLjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24x
        |EDAOBgNVBAUTBzQ2OTk4NTUxETAPBgNVBAMTCGNhc2guYXBwMIIBIjANBgkqhkiG
        |9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqv2iSwWvb6ys/Ru4LtSz0R4wDaxklrFIGqdJ
        |rxxYdAdLQjyjHyJsfkNQdt2u4JYPRKaRTVYR9VIIeWUx/IjhZhsGPstPMjYT3cN1
        |VsphSDtrRVuxYlmkrvHar0HoadNr1MHd96Ach3g1QJlV8uyUJ7JXpPCNJ8EMiH52
        |n8bVzpjDjXwoYg3oOYvceteA0GJ5VWYACDgfmkeoaN1Cx31O9qcSiUk5AY8HfAnP
        |h20VcrnPo2dJmm7fkUKohIxrMjtpwi5esWhCBZJk50FveKrgdeSe4XxNL7uJPD89
        |SJtKmX7jxoNQSY3mrPssLdadwltUOhzc4Lcmoj4Ob24JxuVw8QIDAQABo4IDDzCC
        |AwswIQYDVR0RBBowGIIIY2FzaC5hcHCCDHd3dy5jYXNoLmFwcDCCAX8GCisGAQQB
        |1nkCBAIEggFvBIIBawFpAHcAVhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ
        |0N0AAAFxc9MmmwAABAMASDBGAiEAqeWK3uWt9LX1p3l0gPgNxYBB142oqtRMnMBB
        |anTKy2ICIQDrRj7PRsVyXf1QRxgE5MZl6K6XkBKbaXBlAqPpb8z2hQB3AId1v+dZ
        |fPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9eoIMPAAABcXPTJq0AAAQDAEgwRgIhANRS
        |wAmVQLXhhxbbUTSKIA6P0Q6EmNABCNSJjSK5Q0ItAiEA88hnegYqVaykbbsQSSI0
        |gP/+Odnm/Thso6HEJFXvYGcAdQB9PvL4j/+IVWgkwsDKnlKJeSvFDngJfy5ql2iZ
        |fiLw1wAAAXFz0yazAAAEAwBGMEQCIH4RLAKbk+DbFdHeQO3bmqelXutLSM6MlN34
        |7XEzHpMeAiB4KB48OcjmQ7kBwrxsRwqg7TrQG/F/DyB9wPilq1QacDAOBgNVHQ8B
        |Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMGgGCCsGAQUF
        |BwEBBFwwWjAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZW50cnVzdC5uZXQwMwYI
        |KwYBBQUHMAKGJ2h0dHA6Ly9haWEuZW50cnVzdC5uZXQvbDFtLWNoYWluMjU2LmNl
        |cjAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3JsLmVudHJ1c3QubmV0L2xldmVs
        |MW0uY3JsMEoGA1UdIARDMEEwNgYKYIZIAYb6bAoBAjAoMCYGCCsGAQUFBwIBFhpo
        |dHRwOi8vd3d3LmVudHJ1c3QubmV0L3JwYTAHBgVngQwBATAfBgNVHSMEGDAWgBTD
        |99C1KjCtrw2RIXA5VN28iXDHOjAdBgNVHQ4EFgQUdf0kwt9ZJZnjLzNz4YwEUN0b
        |h7YwCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAQEAYLX6TSuQqSAEu37pJ+au
        |9IlRiAEhtdybxr3mhuII0zImejhLuo2knO2SD59avCDBPivITsSvh2aewOUmeKj1
        |GYI7v16xCOCTQz3k31sCAX2L7DozHtbrY4wG7hUSA9dSv/aYJEtebkwim3lgHwv3
        |NHA3iiW3raH1DPJThQmxFJrnT1zL0LQbM1nRQMXaBVfQEEhIYnrU672x6D/cya6r
        |5UwWye3TOZCH0Lh+YaZqtuKx9lEIEXaxjD3jpGlwRLuE/fI6fXg+0kMvaqNVLmpN
        |aJT7WeHs5bkf0dU7rtDefr0iKeqIxrlURPgbeWZF8GAkpdNaCwWMDAFO8DG04K+t
        |Aw==
        |""".trimMargin()

  @Test
  fun funTestPrettyPrint() {
    val okHttpCertificate =
      CertificateAdapters.certificate.fromDer(certificateBase64.decodeBase64()!!)

    val output = okHttpCertificate.prettyPrintCertificate()

    assertThat(output).isEqualTo("""
      |CN: 	cash.app
      |SHA256:	43a60e5aecabd897cbbcf833150740e18ff0c3d90bde132354dc85a4869b3269
      |SAN: 	cash.app, www.cash.app
      |Key Usage: DigitalSignature, KeyEncipherment
      |Ext Key Usage: serverAuth, clientAuth
      |Valid: 	2020-04-13T13:25:49Z..2021-04-12T13:55:49Z
      |CA: false
    """.trimMargin())
  }
}
