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
package app.cash.certifikit.cli.oscp

import java.lang.IllegalStateException
import okhttp3.HttpUrl
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.RevokedStatus
import picocli.CommandLine

class OcspResponse(
  val requestStatus: app.cash.certifikit.cli.oscp.Status? = null,
  val responseObject: BasicOCSPResp? = null,
  val url: HttpUrl? = null,
  val failure: Exception? = null
) {
  val responseStatus = responseObject?.responses?.firstOrNull()

  enum class Status {
    GOOD, REVOKED, UNKNOWN, FAILED;
  }

  val status: Status
    get() = when {
      requestStatus != app.cash.certifikit.cli.oscp.Status.SUCCESSFUL -> Status.FAILED
      failure != null -> Status.FAILED
      responseStatus?.certStatus == CertificateStatus.GOOD -> Status.GOOD
      responseStatus?.certStatus is RevokedStatus -> Status.REVOKED
      else -> Status.UNKNOWN
    }

  fun prettyPrint(): String {
    return when {
      failure != null -> CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Failed checking OCSP status (${failure.message}) from $url|@")
      status == Status.GOOD -> goodStatus()
      else -> CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Failed checking OCSP status ($status) from $url|@")
    }
  }

  private fun goodStatus(): String {
    val firstResponse = responseObject?.responses?.firstOrNull()

    return if (firstResponse == null) {
      "OCSP status: unknown"
    } else {
      // null == GOOD
      val good = firstResponse.certStatus == CertificateStatus.GOOD

      "OCSP status: GOOD"
    }
  }

  companion object {
    fun failure(reason: String) = OcspResponse(failure = IllegalStateException(reason))
  }
}
