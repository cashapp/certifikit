package app.cash.certifikit.cli.errors

import java.io.IOException

class ClientException(val responseMessage: String, val code: Int) : IOException("$code: $responseMessage")
