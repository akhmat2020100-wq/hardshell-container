package top.niunaijun.blackboxa.app

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File
import java.io.PrintWriter
import java.io.StringWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Writes a plain-text log straight into /sdcard/Download/hardbox-log.txt so it
 * can be pulled without adb. Covers: process boot marker, uncaught exceptions,
 * and any call site we instrument.
 */
object OfxLog {

    private const val FILE_NAME = "hardbox-log.txt"

    @Volatile private var appCtx: Context? = null
    @Volatile private var mediaUri: Uri? = null

    fun install(c: Context) {
        appCtx = c.applicationContext ?: c

        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            write("CRASH thread=${t.name} ${e.javaClass.name}: ${e.message}")
            write(stackOf(e))
            flushAndDie()
        }

        write("boot pid=${android.os.Process.myPid()} sdk=${Build.VERSION.SDK_INT} " +
              "model=${Build.MODEL} abi=${Build.SUPPORTED_ABIS.joinToString(",")}")
    }

    fun log(msg: String) = write(msg)

    private fun flushAndDie() {
        android.os.Process.killProcess(android.os.Process.myPid())
        kotlin.system.exitProcess(10)
    }

    private fun stackOf(e: Throwable): String {
        val sw = StringWriter()
        e.printStackTrace(PrintWriter(sw))
        return sw.toString()
    }

    @Synchronized
    private fun write(msg: String) {
        val line = SimpleDateFormat("HH:mm:ss.SSS", Locale.US).format(Date()) + "  " + msg + "\n"
        val c = appCtx ?: return

        // 1. MediaStore -> visible in /sdcard/Download, no permission on API 29+
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                var uri = mediaUri
                if (uri == null) {
                    val values = ContentValues().apply {
                        put(MediaStore.MediaColumns.DISPLAY_NAME, FILE_NAME)
                        put(MediaStore.MediaColumns.MIME_TYPE, "text/plain")
                        put(MediaStore.MediaColumns.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS)
                    }
                    uri = c.contentResolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    mediaUri = uri
                }
                if (uri != null) {
                    c.contentResolver.openOutputStream(uri, "wa")?.use { it.write(line.toByteArray()) }
                    return
                }
            }
        } catch (_: Throwable) {
            // fall through to internal file
        }

        // 2. Fallback: app-private file
        try {
            File(c.filesDir, FILE_NAME).appendText(line)
        } catch (_: Throwable) {
        }
    }
}
