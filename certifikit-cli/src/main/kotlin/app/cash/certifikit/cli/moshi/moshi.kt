package app.cash.certifikit.cli.moshi

import com.squareup.moshi.JsonAdapter
import com.squareup.moshi.JsonReader
import com.squareup.moshi.JsonWriter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import kotlinx.datetime.Instant
import java.io.IOException

class InstantJsonAdapter : JsonAdapter<kotlinx.datetime.Instant?>() {
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