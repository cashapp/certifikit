package app.cash.certifikit.cli

fun main() {
  // Should match results from https://transparencyreport.google.com/https/certificates
  Main.main("--host", "facebook.com")
  Main.main("--host", "no-sct.badssl.com")
}
