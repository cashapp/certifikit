/*
 * Copyright (C) 2022 Square, Inc.
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

package app.cash.certifikit.cli.okhttp

import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.X509ExtendedTrustManager

class CapturingTrustManager(
  val delegate: X509ExtendedTrustManager,
  val captured: MutableMap<String, List<X509Certificate>>
) : X509ExtendedTrustManager() {

  override fun checkClientTrusted(
    chain: Array<out X509Certificate>,
    authType: String,
    socket: Socket
  ) {
    delegate.checkClientTrusted(chain, authType, socket)
  }

  override fun checkClientTrusted(
    chain: Array<out X509Certificate>,
    authType: String,
    engine: SSLEngine
  ) {
    delegate.checkClientTrusted(chain, authType, engine)
  }

  override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) {
    delegate.checkClientTrusted(chain, authType)
  }

  override fun checkServerTrusted(
    chain: Array<out X509Certificate>,
    authType: String,
    socket: Socket
  ) {
    captured[socket.inetAddress.hostName] = chain.toList()
    delegate.checkServerTrusted(chain, authType, socket)
  }

  override fun checkServerTrusted(
    chain: Array<out X509Certificate>,
    authType: String,
    engine: SSLEngine
  ) {
    delegate.checkServerTrusted(chain, authType, engine)
  }

  override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
    delegate.checkServerTrusted(chain, authType)
  }

  override fun getAcceptedIssuers(): Array<X509Certificate> {
    return delegate.acceptedIssuers
  }
}
