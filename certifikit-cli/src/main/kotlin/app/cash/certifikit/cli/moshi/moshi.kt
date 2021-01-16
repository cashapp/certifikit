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
package app.cash.certifikit.cli.moshi

import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.datetime.Instant
import okhttp3.Response
import java.io.IOException

class InstantJsonAdapter : JsonAdapter<Instant?>() {
  @Synchronized @Throws(IOException::class) override fun fromJson(reader: JsonReader): Instant? {
    if (reader.peek() == JsonReader.Token.NULL) {
      return reader.nextNull()
    }
    val string = reader.nextString()
    // TODO how to do this properly
    return Instant.fromEpochMilliseconds(java.time.Instant.parse(string + "Z").toEpochMilli())
  }

  override fun toJson(writer: JsonWriter, value: Instant?) {
    if (value == null) {
      writer.nullValue()
    } else {
      writer.value(value.toString())
    }
  }
}

val moshi: Moshi = Moshi.Builder()
  .add(Instant::class.java, InstantJsonAdapter())
  .build()

@Suppress("UNCHECKED_CAST")
inline fun <reified T> Moshi.listAdapter() = adapter<Any>(
  Types.newParameterizedType(List::class.java, T::class.java)
) as JsonAdapter<List<T>>


@Suppress("BlockingMethodInNonBlockingContext")
suspend inline fun <reified T> Response.parseList(
) = withContext(Dispatchers.IO) {
  body?.run {
    moshi.listAdapter<T>().fromJson(source())
  }
} ?: throw IOException("Invalid response")