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
package app.cash.certifikit.cli.crl

import app.cash.certifikit.AttributeTypeAndValue
import okhttp3.HttpUrl
import okhttp3.Response
import picocli.CommandLine

class CrlResponse(
  val url: HttpUrl? = null,
  val response: Response? = null,
  val failure: Exception? = null,
  val cRLIssuer: List<AttributeTypeAndValue>? = null
) {
  fun prettyPrint(): String {
    return if (url != null) {
      when {
        failure != null -> CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Failed checking CRL (${failure.message}) from $url|@"
        )
        else -> "CRL: $url size: ${response?.header("Content-Length")} size: ${response?.body?.contentType()}"
      }
    } else if (cRLIssuer != null) {
      "CRL: $cRLIssuer"
    } else {
      CommandLine.Help.Ansi.AUTO.string(
        "@|yellow Failed checking CRL (${failure?.message})|@"
      )
    }
  }
}
