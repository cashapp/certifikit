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

import org.bouncycastle.cert.ocsp.BasicOCSPResp
import picocli.CommandLine

data class OcspResponse(val requestStatus: Status, val responseObject: BasicOCSPResp?) {
  fun prettyPrint(): String {
    return when (requestStatus) {
      Status.SUCCESSFUL -> "OCSP status: ${responseObject?.responses?.firstOrNull()?.certStatus}"
      else -> CommandLine.Help.Ansi.AUTO.string(
          "@|yellow Failed checking OCSP status ($requestStatus)|@")
    }
  }
}
