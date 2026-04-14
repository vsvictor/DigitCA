import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.Base64

fun main() {
    val apiBase = System.getenv("API_BASE") ?: "https://digitca.digit.com"
    val username = System.getenv("USERNAME") ?: "admin"
    val password = System.getenv("PASSWORD") ?: "secret"

    val basic = Base64.getEncoder().encodeToString("$username:$password".toByteArray())
    val client = OkHttpClient()

    fun call(path: String, withAuth: Boolean = false) {
        val requestBuilder = Request.Builder().url("$apiBase$path")
        if (withAuth) requestBuilder.header("Authorization", "Basic $basic")
        client.newCall(requestBuilder.build()).execute().use { resp ->
            println("$path -> ${resp.code}")
            val body = resp.body?.string()?.take(200) ?: ""
            if (body.isNotBlank()) println(body)
        }
    }

    call("/health")
    call("/docs")
    call("/api/v1/certificates?include_revoked=true&page=1&per_page=5", withAuth = true)
}

