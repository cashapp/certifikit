package app.cash.certifikit.cli.graal

import com.oracle.svm.core.annotate.Substitute
import com.oracle.svm.core.annotate.TargetClass
import okhttp3.internal.platform.Jdk9Platform
import okhttp3.internal.platform.Platform

@TargetClass(Platform.Companion::class)
class TargetConsoleHandler {
  @Substitute
  /** Attempt to match the host runtime to a capable Platform implementation. */
  fun findPlatform(): Platform = Jdk9Platform.buildIfSupported()!!
}
