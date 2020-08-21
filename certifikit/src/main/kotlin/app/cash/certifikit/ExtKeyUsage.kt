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
package app.cash.certifikit

data class ExtKeyUsage(val objectIdentifier: String) {
  override fun toString(): String {
    return name ?: objectIdentifier
  }

  val name: String?
  get() {
    return Known[objectIdentifier]
  }

  companion object {
    val Known = mapOf(
        "1.3.6.1.5.5.7.3.1" to "serverAuth",
        "1.3.6.1.5.5.7.3.2" to "clientAuth",
        "1.3.6.1.5.5.7.3.3" to "codeSigning",
        "1.3.6.1.5.5.7.3.4" to "emailProtection",
        "1.3.6.1.5.5.7.3.8" to "timeStamping",
        "1.3.6.1.5.5.7.3.9" to "ocspSigning",
        "1.3.6.1.5.5.7.3.5" to "ipsecEndSystem",
        "1.3.6.1.5.5.7.3.6" to "ipsecTunnel",
        "1.3.6.1.5.5.7.3.7" to "ipsecUser"
    )
  }
}
