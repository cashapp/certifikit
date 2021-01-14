package app.cash.certifikit.cli.ct

import app.cash.certifikit.cli.Main
import app.cash.certifikit.cli.await
import app.cash.certifikit.cli.moshi.listAdapter
import app.cash.certifikit.cli.moshi.moshi
import com.squareup.moshi.JsonClass
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Request
import okhttp3.Response
import java.io.IOException

@JsonClass(generateAdapter = true)
data class CTCertificate(
  val issuer_ca_id: Long,
  val issuer_name: String,
  val common_name: String,
  val name_value: String,
  val id: Long,
  val entry_timestamp: String,
  val not_before: Instant,
  val not_after: Instant,
  val serial_number: String,
)

suspend fun Main.crt(host: String): List<CTCertificate> {
  val adapter = moshi.listAdapter<CTCertificate>()

  val url = "https://crt.sh/?dnsname=$host&match=LIKE&output=json&exclude=expired".toHttpUrl()

  val request = Request.Builder()
    .url(url)
    .build()

  val response = this.client.newCall(request).await()

  return response.use { it.parseList() }
}

@Suppress("BlockingMethodInNonBlockingContext")
private suspend inline fun <reified T> Response.parseList(
) = withContext(Dispatchers.IO) {
  val adapter = moshi.listAdapter<T>()
  adapter.fromJson(body!!.source())
} ?: throw IOException("Invalid response")