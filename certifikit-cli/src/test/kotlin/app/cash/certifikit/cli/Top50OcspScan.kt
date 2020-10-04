package app.cash.certifikit.cli

import app.cash.certifikit.cli.oscp.OcspClient
import app.cash.certifikit.cli.oscp.OcspResponse
import java.io.File
import java.util.concurrent.TimeUnit
import kotlin.system.exitProcess
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import okhttp3.OkHttpClient

suspend fun main() {
  coroutineScope {
    // https://en.wikipedia.org/wiki/List_of_most_popular_websites
    val hosts = File("certifikit-cli/src/test/resources/top50.csv").readLines()

    val client = OkHttpClient.Builder().callTimeout(2, TimeUnit.SECONDS).build()
    val ocspClient = OcspClient(client, secure = false)

    val requests = hosts.map { host ->
      Pair(host, async { ocspClient.submit(host) })
    }

    requests.forEach { (host, pendingResponse) ->
      val response = pendingResponse.await()

      if (response.status != OcspResponse.Status.GOOD) {
        println("$host\t${response.prettyPrint()}")
      } else {
        println("$host")
      }
    }
  }
  exitProcess(1)
}
