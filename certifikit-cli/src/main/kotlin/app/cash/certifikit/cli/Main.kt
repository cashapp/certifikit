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

import app.cash.certifikit.Certifikit
import app.cash.certifikit.cli.Main.Companion.NAME
import app.cash.certifikit.cli.Main.VersionProvider
import app.cash.certifikit.cli.errors.CertificationException
import app.cash.certifikit.cli.errors.UsageException
import java.io.File
import java.util.concurrent.Callable
import kotlin.system.exitProcess
import kotlinx.coroutines.runBlocking
import okhttp3.internal.platform.Platform
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Help.Ansi
import picocli.CommandLine.IVersionProvider
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters

@Command(
  name = NAME, description = ["An ergonomic CLI for understanding certificates."],
  mixinStandardHelpOptions = true, versionProvider = VersionProvider::class
)
class Main : Callable<Int> {
  @Option(names = ["--host"], description = ["From HTTPS Handshake"])
  var host: String? = null

  @Option(names = ["--verbose"], description = ["Verbose Output"])
  var verbose: Boolean = false

  @Option(names = ["--insecure"], description = ["Insecure HTTPS"])
  var insecure: Boolean = false

  @Option(names = ["--redirect"], description = ["Follow redirects"])
  var followRedirects: Boolean = false

  @Option(names = ["--output", "-o"], description = ["Output file or directory"])
  var output: File? = null

  @Option(names = ["--keystore"], description = ["Keystore for local verification"])
  var keyStoreFile: File? = null

  @Option(names = ["--complete"], description = ["Complete option"])
  var complete: String? = null

  @Parameters(paramLabel = "file", description = ["Input File"], arity = "0..1")
  var file: String? = null

  @Option(names = ["--all"], description = ["Fetch from all DNS hosts"])
  var allHosts: Boolean = false

  val trustManager by lazy {
    keyStoreFile?.trustManager() ?: Platform.get().platformTrustManager()
  }

  val client by lazy {
    buildClient()
  }

  override fun call(): Int {
    try {
      when {
        complete != null -> {
          completeOption()
        }
        host != null -> {
          runBlocking { queryHost(host!!) }
        }
        file != null -> {
          runBlocking { showPemFile(file!!) }
        }
        else -> {
          throw UsageException("No action to run")
        }
      }
      return 0
    } catch (ce: CertificationException) {
      System.err.println("Error: ${Ansi.AUTO.string(" @|yellow ${ce.message}|@")}")
      if (verbose) {
        ce.cause?.printStackTrace()
      }
      return -2
    } catch (ue: UsageException) {
      System.err.println("Error: ${Ansi.AUTO.string(" @|red ${ue.message}|@")}")
      if (verbose) {
        ue.cause?.printStackTrace()
      }
      return -1
    }
  }

  private suspend fun showPemFile(filename: String) {
    val certificates = if (filename == "-") {
      val stdInText = System.`in`.bufferedReader().readText()
      listOf(stdInText.parsePemCertificate())
    } else if (filename.startsWith("https://") || filename.startsWith("http://")) {
      fetchCertificates(filename)
    } else {
      listOf(File(filename).parsePemCertificate())
    }

    certificates.forEachIndexed { index, certificate ->
      if (index != 0) println()

      println(certificate.prettyPrintCertificate(trustManager))
    }

    val additionalCertificatesUrl =
      certificates.singleOrNull()?.caIssuers

    if (additionalCertificatesUrl != null) {
      val chain = fetchCertificates(additionalCertificatesUrl, fullChain = true)
      chain.forEach { certificate ->
        println()
        println(certificate.prettyPrintCertificate(trustManager))
      }
    }
  }

  private fun completeOption() {
    if (complete == "host") {
      for (host in knownHosts()) {
        println(host)
      }
    }
  }

  internal fun addHostToCompletionFile(host: String) {
    val previousHosts = knownHosts()
    val newHosts = previousHosts + host

    val lineSeparator = System.getProperty("line.separator")
    knownHostsFile.writeText(newHosts.joinToString(lineSeparator, postfix = lineSeparator))
  }

  private fun knownHosts(): Set<String> {
    return if (knownHostsFile.isFile) {
      knownHostsFile.readLines().filter { it.trim().isNotBlank() }.toSortedSet()
    } else {
      setOf()
    }
  }

  class VersionProvider : IVersionProvider {
    override fun getVersion(): Array<String> {
      return arrayOf("$NAME ${Certifikit.VERSION}")
    }
  }

  companion object {
    internal const val NAME = "cft"

    val confDir = File(System.getProperty("user.home"), ".cft").also {
      if (!it.isDirectory) {
        it.mkdirs()
      }
    }
    val knownHostsFile = File(confDir, "knownhosts.txt")

    @JvmStatic
    fun main(vararg args: String) {
      exitProcess(CommandLine(Main()).execute(*args))
    }
  }
}
