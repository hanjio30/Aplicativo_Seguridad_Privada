package com.example.seguridad_priv_a.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Debug
import android.util.Base64
import java.io.File
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.*
import java.net.URL
import java.security.KeyStore
import java.security.cert.CertificateFactory
import kotlinx.coroutines.*

/**
 * Anti-Tampering Manager
 * Protege contra ingeniería inversa, debugging y manipulación
 */
class AntiTamperingManager(private val context: Context) {

    private val obfuscatedStrings = mutableMapOf<String, String>()
    private val pinnedCertificates = mutableMapOf<String, String>()

    companion object {
        // Strings obfuscados - en producción usar herramientas de obfuscación más avanzadas
        private const val DEBUG_FLAG = "ZGVidWdfZmxhZw=="
        private const val EMULATOR_CHECK = "ZW11bGF0b3JfY2hlY2s="
        private const val ROOT_CHECK = "cm9vdF9jaGVjaw=="
        private const val HOOK_DETECTION = "aG9va19kZXRlY3Rpb24="

        // Claves obfuscadas (en producción usar HSM o keystore hardware)
        private const val ENC_KEY = "bXlfc3VwZXJfc2VjcmV0X2tleV8xMjPQ"
        private const val HMAC_KEY = "aG1hY19rZXlfZm9yX3NlY3VyaXR5XzQ1Ng=="
    }

    data class TamperingDetectionResult(
        val isCompromised: Boolean,
        val detectedThreats: List<String>,
        val riskLevel: RiskLevel,
        val recommendedAction: String
    )

    enum class RiskLevel { LOW, MEDIUM, HIGH, CRITICAL }

    fun initialize() {
        setupObfuscatedStrings()
        setupCertificatePinning()
        startAntiTamperingMonitoring()
    }

    private fun setupObfuscatedStrings() {
        // Desobfuscar strings críticos en runtime
        obfuscatedStrings["debug"] = deobfuscateString(DEBUG_FLAG)
        obfuscatedStrings["emulator"] = deobfuscateString(EMULATOR_CHECK)
        obfuscatedStrings["root"] = deobfuscateString(ROOT_CHECK)
        obfuscatedStrings["hook"] = deobfuscateString(HOOK_DETECTION)
    }

    private fun setupCertificatePinning() {
        // Configurar certificate pinning para APIs futuras
        pinnedCertificates["api.example.com"] = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        pinnedCertificates["secure.example.com"] = "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    }

    private fun deobfuscateString(encoded: String): String {
        return try {
            String(Base64.decode(encoded, Base64.DEFAULT))
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Detección comprehensiva de tampering
     */
    suspend fun detectTampering(): TamperingDetectionResult = withContext(Dispatchers.Default) {
        val threats = mutableListOf<String>()
        var riskLevel = RiskLevel.LOW

        // 1. Detección de debugging activo
        if (detectActiveDebugging()) {
            threats.add("Active debugging detected")
            riskLevel = RiskLevel.HIGH
        }

        // 2. Detección de emulador
        if (detectEmulator()) {
            threats.add("Running on emulator")
            riskLevel = maxOf(riskLevel, RiskLevel.MEDIUM)
        }

        // 3. Detección de root
        if (detectRoot()) {
            threats.add("Device is rooted")
            riskLevel = maxOf(riskLevel, RiskLevel.HIGH)
        }

        // 4. Detección de hooks y modificaciones
        if (detectHooksAndModifications()) {
            threats.add("Runtime hooks detected")
            riskLevel = maxOf(riskLevel, RiskLevel.CRITICAL)
        }

        // 5. Verificación de integridad del APK
        if (!verifyApkIntegrity()) {
            threats.add("APK integrity compromised")
            riskLevel = maxOf(riskLevel, RiskLevel.CRITICAL)
        }

        // 6. Detección de herramientas de análisis
        if (detectAnalysisTools()) {
            threats.add("Analysis tools detected")
            riskLevel = maxOf(riskLevel, RiskLevel.HIGH)
        }

        val recommendedAction = when (riskLevel) {
            RiskLevel.LOW -> "Continue normal operation"
            RiskLevel.MEDIUM -> "Enhanced monitoring recommended"
            RiskLevel.HIGH -> "Limit sensitive operations"
            RiskLevel.CRITICAL -> "Terminate application immediately"
        }

        TamperingDetectionResult(
            isCompromised = threats.isNotEmpty(),
            detectedThreats = threats,
            riskLevel = riskLevel,
            recommendedAction = recommendedAction
        )
    }

    /**
     * Detección de debugging activo - Múltiples técnicas
     */
    private fun detectActiveDebugging(): Boolean {
        // Técnica 1: Verificar flag de debug
        if (Debug.isDebuggerConnected()) {
            return true
        }

        // Técnica 2: Verificar si la aplicación está marcada como debuggable
        if ((context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
            return true
        }

        // Técnica 3: Verificar timing de ejecución (debugging suele ser más lento)
        val startTime = System.nanoTime()
        val iterations = 1000000
        for (i in 0 until iterations) {
            // Operación simple para medir timing
            Math.sqrt(i.toDouble())
        }
        val endTime = System.nanoTime()
        val executionTime = endTime - startTime

        // Si toma demasiado tiempo, posible debugging
        if (executionTime > iterations * 1000) { // Umbral ajustable
            return true
        }

        // Técnica 4: Verificar puertos de debug
        return checkDebugPorts()
    }

    private fun checkDebugPorts(): Boolean {
        val debugPorts = listOf(5005, 8000, 8787, 9999)
        return debugPorts.any { port ->
            try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 100)
                socket.close()
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    /**
     * Detección avanzada de emulador
     */
    private fun detectEmulator(): Boolean {
        // Verificar Build properties
        val emulatorBuilds = listOf(
            Build.FINGERPRINT.startsWith("generic"),
            Build.FINGERPRINT.startsWith("unknown"),
            Build.FINGERPRINT.contains("emulator"),
            Build.MODEL.contains("google_sdk"),
            Build.MODEL.contains("Emulator"),
            Build.MODEL.contains("Android SDK"),
            Build.MANUFACTURER.contains("Genymotion"),
            Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"),
            "google_sdk" == Build.PRODUCT,
            Build.HARDWARE.contains("goldfish"),
            Build.HARDWARE.contains("ranchu")
        )

        if (emulatorBuilds.any { it }) {
            return true
        }

        // Verificar archivos específicos de emulador
        val emulatorFiles = listOf(
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/proc/tty/drivers",
            "/proc/cpuinfo"
        )

        return emulatorFiles.any { file ->
            try {
                File(file).exists()
            } catch (e: Exception) {
                false
            }
        }
    }

    /**
     * Detección de root/jailbreak
     */
    private fun detectRoot(): Boolean {
        // Verificar archivos comunes de root
        val rootFiles = listOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su",
            "/system/xbin/busybox",
            "/system/bin/busybox"
        )

        if (rootFiles.any { file ->
                try {
                    File(file).exists()
                } catch (e: Exception) {
                    false
                }
            }) {
            return true
        }

        // Verificar aplicaciones de root
        val rootApps = listOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk",
            "com.kingroot.kinguser",
            "com.kingo.root"
        )

        return rootApps.any { app ->
            try {
                context.packageManager.getPackageInfo(app, 0)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false
            }
        }
    }

    /**
     * Detección de hooks y modificaciones runtime
     */
    private fun detectHooksAndModifications(): Boolean {
        // Verificar Xposed Framework
        if (detectXposed()) {
            return true
        }

        // Verificar Frida
        if (detectFrida()) {
            return true
        }

        // Verificar Substrate
        if (detectSubstrate()) {
            return true
        }

        // Verificar modificaciones en métodos críticos
        return detectMethodHooks()
    }

    private fun detectXposed(): Boolean {
        return try {
            Class.forName("de.robv.android.xposed.XposedHelpers")
            true
        } catch (e: ClassNotFoundException) {
            // Verificar archivos de Xposed
            File("/system/framework/XposedBridge.jar").exists()
        }
    }

    private fun detectFrida(): Boolean {
        // Verificar librerías de Frida
        val fridaLibs = listOf(
            "frida-agent",
            "frida-gadget",
            "frida-helper"
        )

        return fridaLibs.any { lib ->
            try {
                System.loadLibrary(lib)
                true
            } catch (e: UnsatisfiedLinkError) {
                false
            }
        } || checkFridaPorts()
    }

    private fun checkFridaPorts(): Boolean {
        val fridaPorts = listOf(27042, 27043, 27044)
        return fridaPorts.any { port ->
            try {
                val socket = java.net.Socket()
                socket.connect(java.net.InetSocketAddress("127.0.0.1", port), 100)
                socket.close()
                true
            } catch (e: Exception) {
                false
            }
        }
    }

    private fun detectSubstrate(): Boolean {
        return try {
            Class.forName("com.saurik.substrate.MS")
            true
        } catch (e: ClassNotFoundException) {
            File("/system/lib/libsubstrate.so").exists() ||
                    File("/system/lib64/libsubstrate.so").exists()
        }
    }

    private fun detectMethodHooks(): Boolean {
        // Verificar si métodos críticos han sido modificados
        return try {
            val originalMethod = this::class.java.getDeclaredMethod("detectMethodHooks")
            val modifiers = originalMethod.modifiers

            // Verificar si el método tiene modificadores inesperados
            java.lang.reflect.Modifier.isNative(modifiers) ||
                    java.lang.reflect.Modifier.isAbstract(modifiers)
        } catch (e: Exception) {
            true // Si no podemos verificar, asumir compromiso
        }
    }

    /**
     * Verificación de integridad del APK
     */
    private fun verifyApkIntegrity(): Boolean {
        return try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, 0)
            val sourceDir = packageInfo.applicationInfo?.sourceDir
            val apkFile = File(sourceDir)

            // Calcular hash del APK
            val currentHash = calculateFileHash(apkFile)
            val expectedHash = getExpectedApkHash()

            currentHash == expectedHash
        } catch (e: Exception) {
            false
        }
    }

    private fun calculateFileHash(file: File): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            Base64.encodeToString(digest.digest(), Base64.NO_WRAP)
        } catch (e: Exception) {
            ""
        }
    }

    private fun getExpectedApkHash(): String {
        // En producción, esto debería ser el hash real de tu APK
        return deobfuscateString("RVhQRUNURURfQVBLX0hBU0hfUExBQ0VIT0xERVI=")
    }

    /**
     * Detección de herramientas de análisis
     */
    private fun detectAnalysisTools(): Boolean {
        val analysisTools = listOf(
            "com.android.ddms",
            "com.android.hierarchyviewer",
            "com.android.traceview",
            "jadx.gui.JadxGUI",
            "com.googlecode.dex2jar",
            "brut.apktool.Main"
        )

        return analysisTools.any { tool ->
            try {
                Class.forName(tool)
                true
            } catch (e: ClassNotFoundException) {
                false
            }
        }
    }

    private fun startAntiTamperingMonitoring() {
        // Iniciar monitoreo continuo en background
        CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                delay(30000) // Verificar cada 30 segundos

                val result = detectTampering()
                if (result.isCompromised && result.riskLevel == RiskLevel.CRITICAL) {
                    // Notificar a la aplicación principal
                    handleCriticalThreat(result)
                }
            }
        }
    }

    private fun handleCriticalThreat(result: TamperingDetectionResult) {
        // En caso de amenaza crítica, tomar medidas inmediatas
        // Como borrar datos sensibles, cerrar la aplicación, etc.

        // Por ahora, solo registrar el evento
        logSecurityEvent("CRITICAL_THREAT_DETECTED", result.detectedThreats.joinToString(","))
    }

    /**
     * Certificate Pinning Implementation
     */
    fun createPinnedSSLContext(hostname: String): SSLContext? {
        val pinnedCert = pinnedCertificates[hostname] ?: return null

        return try {
            val trustManager = object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}

                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                    if (chain.isEmpty()) {
                        throw SSLException("Certificate chain is empty")
                    }

                    val serverCert = chain[0]
                    val certHash = calculateCertificateHash(serverCert)

                    if (certHash != pinnedCert) {
                        throw SSLException("Certificate pinning failure for $hostname")
                    }
                }

                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            }

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(trustManager), null)
            sslContext
        } catch (e: Exception) {
            null
        }
    }

    private fun calculateCertificateHash(cert: X509Certificate): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(cert.encoded)
        return "sha256/" + Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Validación de conexión con certificate pinning
     */
    fun validatePinnedConnection(url: String): Boolean {
        return try {
            val uri = URL(url)
            val hostname = uri.host
            val sslContext = createPinnedSSLContext(hostname) ?: return false

            val connection = uri.openConnection() as HttpsURLConnection
            connection.sslSocketFactory = sslContext.socketFactory
            connection.hostnameVerifier = HostnameVerifier { _, _ -> true }

            connection.connect()
            val responseCode = connection.responseCode
            connection.disconnect()

            responseCode in 200..299
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Obfuscación de strings sensibles en runtime
     */
    fun obfuscateString(input: String, key: String = "default"): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val secretKey = SecretKeySpec(key.padEnd(16, '0').take(16).toByteArray(), "AES")
            val iv = ByteArray(16) { 0 } // En producción usar IV aleatorio

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
            val encrypted = cipher.doFinal(input.toByteArray())
            Base64.encodeToString(encrypted, Base64.NO_WRAP)
        } catch (e: Exception) {
            input // Fallback en caso de error
        }
    }

    fun deobfuscateSecureString(encrypted: String, key: String = "default"): String {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            val secretKey = SecretKeySpec(key.padEnd(16, '0').take(16).toByteArray(), "AES")
            val iv = ByteArray(16) { 0 }

            cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
            val decrypted = cipher.doFinal(Base64.decode(encrypted, Base64.NO_WRAP))
            String(decrypted)
        } catch (e: Exception) {
            "" // Retornar vacío en caso de error
        }
    }

    /**
     * Verificación de firma digital en runtime
     */
    fun verifyRuntimeSignature(): Boolean {
        return try {
            val packageInfo = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNING_CERTIFICATES
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.GET_SIGNATURES
                )
            }

            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo.signingInfo?.apkContentsSigners
            } else {
                @Suppress("DEPRECATION")
                packageInfo.signatures
            }

            signatures?.let { sigs ->
                val expectedSignatures = getExpectedSignatures()
                sigs.any { signature ->
                    val signatureHash = calculateSignatureHash(signature.toByteArray())
                    expectedSignatures.contains(signatureHash)
                }
            } ?: false
        } catch (e: Exception) {
            false
        }
    }

    private fun getExpectedSignatures(): Set<String> {
        // En producción, estas serían las firmas reales de tu aplicación
        return setOf(
            deobfuscateString("RVhQRUNURURfU0lHTkFUVVJFXzE="),
            deobfuscateString("RVhQRUNURURfU0lHTkFUVVJFXzI=")
        )
    }

    private fun calculateSignatureHash(signatureBytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(signatureBytes)
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Anti-debugging en tiempo real
     */
    fun enableAntiDebugging() {
        // Técnica 1: Verificar continuamente el estado de debug
        CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                if (Debug.isDebuggerConnected()) {
                    handleDebugDetection()
                }
                delay(1000)
            }
        }

        // Técnica 2: Verificar timing attacks
        startTimingBasedDetection()
    }

    private fun startTimingBasedDetection() {
        CoroutineScope(Dispatchers.Default).launch {
            while (true) {
                val startTime = System.nanoTime()

                // Operación de referencia
                repeat(10000) {
                    Math.sqrt(it.toDouble())
                }

                val endTime = System.nanoTime()
                val duration = endTime - startTime

                // Si la duración es anormalmente larga, posible debugging
                if (duration > 50_000_000) { // 50ms threshold
                    handleDebugDetection()
                }

                delay(5000)
            }
        }
    }

    private fun handleDebugDetection() {
        logSecurityEvent("DEBUG_DETECTED", "Active debugging session detected")

        // En producción, podrías:
        // 1. Cerrar la aplicación
        // 2. Borrar datos sensibles
        // 3. Enviar alerta al servidor
        // 4. Mostrar pantalla de error
    }

    private fun logSecurityEvent(eventType: String, details: String) {
        // Registrar evento de seguridad para auditoría
        val timestamp = System.currentTimeMillis()
        println("SECURITY_EVENT [$timestamp]: $eventType - $details")
    }

    /**
     * Detección de manipulación de memoria
     */
    fun detectMemoryTampering(): Boolean {
        return try {
            // Verificar integridad de datos críticos en memoria
            val testValue = "INTEGRITY_CHECK_VALUE"
            val storedHash = calculateStringHash(testValue)

            // Simular acceso a memoria y verificar integridad
            Thread.sleep(100)

            val currentHash = calculateStringHash(testValue)
            storedHash != currentHash
        } catch (e: Exception) {
            true // Asumir tampering si hay error
        }
    }

    private fun calculateStringHash(input: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(input.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Protección contra ataques de reflection
     */
    fun protectAgainstReflection() {
        // Detectar uso sospechoso de reflection
        val securityManager = object : SecurityManager() {
            override fun checkMemberAccess(clazz: Class<*>?, which: Int) {
                if (which == java.lang.reflect.Member.DECLARED) {
                    val stackTrace = Thread.currentThread().stackTrace
                    val suspiciousClasses = listOf("java.lang.reflect", "frida", "xposed")

                    stackTrace.forEach { element ->
                        if (suspiciousClasses.any { element.className.contains(it, true) }) {
                            logSecurityEvent("REFLECTION_ATTACK", "Suspicious reflection access detected")
                            throw SecurityException("Reflection access denied")
                        }
                    }
                }
                super.checkMemberAccess(clazz, which)
            }
        }

        try {
            System.setSecurityManager(securityManager)
        } catch (e: Exception) {
            // SecurityManager no siempre está disponible en Android
            logSecurityEvent("SECURITY_MANAGER", "Could not set security manager: ${e.message}")
        }
    }
}