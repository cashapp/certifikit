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

import app.cash.certifikit.Certificate
import app.cash.certifikit.Certifikit
import app.cash.certifikit.cli.Main.Companion.NAME
import app.cash.certifikit.cli.Main.VersionProvider
import app.cash.certifikit.cli.errors.CertificationException
import app.cash.certifikit.cli.errors.ClientException
import app.cash.certifikit.cli.errors.UsageException
import app.cash.certifikit.cli.oscp.ocsp
import app.cash.certifikit.cli.oscp.toCertificate
import app.cash.certifikit.text.certificatePem
import java.io.File
import java.io.IOException
import java.util.concurrent.Callable
import kotlin.system.exitProcess
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import okhttp3.MediaType
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Response
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

  @Option(names = ["--output"], description = ["Output file or directory"])
  var output: File? = null

  @Option(names = ["--keystore"], description = ["Keystore for local verification"])
  var keyStoreFile: File? = null

  @Option(names = ["--complete"], description = ["Complete option"])
  var complete: String? = null

  @Parameters(paramLabel = "file", description = ["Input File"], arity = "0..1")
  var file: String? = null

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
          runBlocking { queryHost() }
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
    val certificate = if (filename == "-") {
      val stdInText = System.`in`.bufferedReader().readText()
      stdInText.parsePemCertificate()
    } else if (filename.startsWith("https://") || filename.startsWith("http://")) {
      fetchPemUrl(filename)
    } else {
      File(filename).parsePemCertificate()
    }

    println(certificate.prettyPrintCertificate(trustManager))
  }

  private suspend fun fetchPemUrl(url: String): Certificate {
    try {
      return client.execute(url.request()).use {
        if (it.body?.contentType() != "application/x-pem-file".toMediaType()) {
          throw UsageException(
            "Response returned: " + it.body?.contentType() + " expecting application/x-pem-file."
          )
        }
        it.bodyString().parsePemCertificate()
      }
    } catch (ce: ClientException) {
      throw UsageException("Request Failed: " + ce.message)
    }
  }

  private fun completeOption() {
    if (complete == "host") {
      for (host in knownHosts()) {
        println(host)
      }
    }
  }

  private suspend fun queryHost() {
    coroutineScope {
      val siteResponse = fromHttps(host!!)

      if (siteResponse.peerCertificates.isEmpty()) {
        System.err.println("Warn: ${Ansi.AUTO.string(" @|yellow No trusted certificates|@")}")
      }

      val ocspResponse = ocsp(client, siteResponse)

      val output = output

      siteResponse.peerCertificates.forEachIndexed { i, certificate ->
        if (i > 0) {
          println()
        }

        if (output != null) {
          val outputFile = when {
            output.isDirectory -> File(output, "${certificate.publicKeySha256().hex()}.pem")
            output.path == "-" -> output
            i > 0 -> {
              System.err.println(Ansi.AUTO.string(
                  "@|yellow Writing host certificate only, skipping (${certificate.subjectX500Principal.name})|@"))
              null
            }
            else -> output
          }

          if (outputFile != null) {
            if (outputFile.path == "-") {
              println(certificate.certificatePem())
            } else {
              try {
                certificate.writePem(outputFile)
              } catch (ioe: IOException) {
                throw UsageException("Unable to write to $output", ioe)
              }
            }
          }
        }

        println(certificate.toCertificate().prettyPrintCertificate(trustManager))
      }

      if (siteResponse.strictTransportSecurity != null) {
        println()
        println("Strict Transport Security: ${siteResponse.strictTransportSecurity}")
      } // TODO We should add SANs and complete wildcard hosts.
      addHostToCompletionFile(host!!)

      try {
        val response = ocspResponse.await()

        // null if no url to check.
        if (response != null) {
          println()
          println(response.prettyPrint())
        }
      } catch (e: Exception) {
        System.err.println(Ansi.AUTO.string(
            "@|yellow Failed checking OCSP status (${e.message})|@"))
      }
    }
  }

  private fun addHostToCompletionFile(host: String) {
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
