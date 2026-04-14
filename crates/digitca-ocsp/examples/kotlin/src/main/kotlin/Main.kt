/**
 * OCSP client example for digitca-ocsp — Kotlin (JVM, stdlib only)
 *
 * Usage:
 *   gradle -q run --args="--ocsp-base http://localhost:8082 \
 *                          --request-der ./request.der \
 *                          --response-der ./response.der"
 *
 * Environment variable overrides:
 *   OCSP_BASE, OCSP_REQUEST_DER, OCSP_RESPONSE_DER
 */
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Files
import java.nio.file.Path

private fun argValue(args: Array<String>, name: String, fallback: String): String {
    val idx = args.indexOf(name)
    return if (idx >= 0 && idx + 1 < args.size) args[idx + 1] else fallback
}

fun main(args: Array<String>) {
    val ocspBase = argValue(args, "--ocsp-base",
        System.getenv("OCSP_BASE") ?: "http://localhost:8082")
    val requestDer = argValue(args, "--request-der",
        System.getenv("OCSP_REQUEST_DER") ?: "./request.der")
    val responseDer = argValue(args, "--response-der",
        System.getenv("OCSP_RESPONSE_DER") ?: "./response.der")

    val client = HttpClient.newHttpClient()

    // 1) Health check
    println("[kotlin] GET $ocspBase/health")
    val healthReq = HttpRequest.newBuilder()
        .uri(URI.create("$ocspBase/health"))
        .GET()
        .build()
    val healthResp = client.send(healthReq, HttpResponse.BodyHandlers.ofString())
    check(healthResp.statusCode() in 200..299) {
        "health failed: ${healthResp.statusCode()}"
    }
    println(healthResp.body())

    // 2) Read request DER
    val requestBytes = Files.readAllBytes(Path.of(requestDer))
    println("[kotlin] POST $ocspBase/ocsp  (${requestBytes.size} bytes)")

    // 3) POST OCSP request
    val ocspReq = HttpRequest.newBuilder()
        .uri(URI.create("$ocspBase/ocsp"))
        .header("Content-Type", "application/ocsp-request")
        .POST(HttpRequest.BodyPublishers.ofByteArray(requestBytes))
        .build()
    val ocspResp = client.send(ocspReq, HttpResponse.BodyHandlers.ofByteArray())
    check(ocspResp.statusCode() in 200..299) {
        "ocsp failed: ${ocspResp.statusCode()}"
    }

    // 4) Save DER response
    Files.write(Path.of(responseDer), ocspResp.body())
    println("[kotlin] OCSP response saved: $responseDer  (${ocspResp.body().size} bytes)")
}

