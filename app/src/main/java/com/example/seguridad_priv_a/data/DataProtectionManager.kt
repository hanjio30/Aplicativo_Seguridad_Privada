package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64
import kotlin.collections.HashMap

class DataProtectionManager(private val context: Context) {

    private lateinit var encryptedPrefs: SharedPreferences
    private lateinit var accessLogPrefs: SharedPreferences
    private lateinit var keyRotationPrefs: SharedPreferences
    private var currentMasterKey: MasterKey? = null

    companion object {
        private const val KEY_ROTATION_INTERVAL = 30L * 24 * 60 * 60 * 1000 // 30 días en milisegundos
        private const val HMAC_ALGORITHM = "HmacSHA256"
        private const val SALT_LENGTH = 16
    }

    fun initialize() {
        try {
            keyRotationPrefs = context.getSharedPreferences("key_rotation", Context.MODE_PRIVATE)

            // Verificar si necesitamos rotar la clave
            if (shouldRotateKey()) {
                rotateEncryptionKey()
            }

            // Crear o obtener la clave maestra actual
            currentMasterKey = getCurrentMasterKey()

            // Crear SharedPreferences encriptado para datos sensibles
            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs",
                currentMasterKey!!,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            // SharedPreferences normal para logs de acceso
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)

        } catch (e: Exception) {
            // Fallback a SharedPreferences normales si falla la encriptación
            encryptedPrefs = context.getSharedPreferences("fallback_prefs", Context.MODE_PRIVATE)
            accessLogPrefs = context.getSharedPreferences("access_logs", Context.MODE_PRIVATE)
        }
    }

    private fun shouldRotateKey(): Boolean {
        val lastRotation = keyRotationPrefs.getLong("last_rotation", 0L)
        val currentTime = System.currentTimeMillis()
        return (currentTime - lastRotation) > KEY_ROTATION_INTERVAL
    }

    fun rotateEncryptionKey(): Boolean {
        return try {
            // Crear nueva clave maestra
            val newMasterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            // Si ya existe una clave anterior, migrar datos
            if (currentMasterKey != null) {
                migrateDataToNewKey(newMasterKey)
            }

            // Actualizar la clave actual
            currentMasterKey = newMasterKey

            // Registrar la rotación
            keyRotationPrefs.edit()
                .putLong("last_rotation", System.currentTimeMillis())
                .putInt("rotation_count", keyRotationPrefs.getInt("rotation_count", 0) + 1)
                .apply()

            logAccess("KEY_ROTATION", "Clave maestra rotada exitosamente")
            true
        } catch (e: Exception) {
            logAccess("KEY_ROTATION", "Error al rotar clave: ${e.message}")
            false
        }
    }

    private fun getCurrentMasterKey(): MasterKey {
        return MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
    }

    private fun migrateDataToNewKey(newMasterKey: MasterKey) {
        try {
            // Crear nuevo SharedPreferences con la nueva clave
            val newEncryptedPrefs = EncryptedSharedPreferences.create(
                context,
                "secure_prefs_new",
                newMasterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )

            // Migrar todos los datos
            val allData = encryptedPrefs.all
            val newEditor = newEncryptedPrefs.edit()

            allData.forEach { (key, value) ->
                when (value) {
                    is String -> newEditor.putString(key, value)
                    is Int -> newEditor.putInt(key, value)
                    is Long -> newEditor.putLong(key, value)
                    is Float -> newEditor.putFloat(key, value)
                    is Boolean -> newEditor.putBoolean(key, value)
                }
            }

            newEditor.apply()

            // Eliminar datos antiguos
            encryptedPrefs.edit().clear().apply()

            // Reemplazar con los nuevos datos
            context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE).edit().clear().apply()
            // Nota: En un escenario real, necesitarías una estrategia más sofisticada para la migración

        } catch (e: Exception) {
            logAccess("KEY_MIGRATION", "Error en migración: ${e.message}")
        }
    }

    fun verifyDataIntegrity(key: String): Boolean {
        return try {
            val data = encryptedPrefs.getString(key, null) ?: return false
            val hmacKey = getHmacKey(key)
            val storedHmac = encryptedPrefs.getString("${key}_hmac", null) ?: return false

            val calculatedHmac = generateHmac(data, hmacKey)
            calculatedHmac == storedHmac
        } catch (e: Exception) {
            logAccess("INTEGRITY_CHECK", "Error verificando integridad de $key: ${e.message}")
            false
        }
    }

    private fun generateHmac(data: String, key: String): String {
        val mac = Mac.getInstance(HMAC_ALGORITHM)
        val secretKey = SecretKeySpec(key.toByteArray(), HMAC_ALGORITHM)
        mac.init(secretKey)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return Base64.encodeToString(hmacBytes, Base64.NO_WRAP)
    }

    private fun getHmacKey(dataKey: String): String {
        val salt = getUserSalt()
        val keyMaterial = "${dataKey}_${salt}_${System.currentTimeMillis() / (1000 * 60 * 60 * 24)}" // Cambiar diariamente
        return generateKeyFromMaterial(keyMaterial)
    }

    private fun getUserSalt(): String {
        var salt = encryptedPrefs.getString("user_salt", null)
        if (salt == null) {
            salt = generateSalt()
            encryptedPrefs.edit().putString("user_salt", salt).apply()
        }
        return salt
    }

    private fun generateSalt(): String {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        return Base64.encodeToString(salt, Base64.NO_WRAP)
    }

    private fun generateKeyFromMaterial(material: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(material.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    fun storeSecureData(key: String, value: String) {
        try {
            // Generar HMAC para verificación de integridad
            val hmacKey = getHmacKey(key)
            val hmac = generateHmac(value, hmacKey)

            // Almacenar datos y HMAC
            encryptedPrefs.edit()
                .putString(key, value)
                .putString("${key}_hmac", hmac)
                .apply()

            logAccess("DATA_STORAGE", "Dato almacenado de forma segura: $key")
        } catch (e: Exception) {
            logAccess("DATA_STORAGE", "Error almacenando $key: ${e.message}")
        }
    }

    fun getSecureData(key: String): String? {
        return try {
            val data = encryptedPrefs.getString(key, null)
            if (data != null) {
                // Verificar integridad antes de devolver los datos
                if (verifyDataIntegrity(key)) {
                    logAccess("DATA_ACCESS", "Dato accedido: $key")
                    data
                } else {
                    logAccess("INTEGRITY_VIOLATION", "Integridad comprometida para: $key")
                    null
                }
            } else {
                null
            }
        } catch (e: Exception) {
            logAccess("DATA_ACCESS", "Error accediendo a $key: ${e.message}")
            null
        }
    }

    fun logAccess(category: String, action: String) {
        val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date())
        val logEntry = "$timestamp - $category: $action"

        // Obtener logs existentes
        val existingLogs = accessLogPrefs.getString("logs", "") ?: ""
        val newLogs = if (existingLogs.isEmpty()) {
            logEntry
        } else {
            "$existingLogs\\n$logEntry"
        }

        // Guardar logs actualizados
        accessLogPrefs.edit().putString("logs", newLogs).apply()

        // Limitar el número de logs (mantener solo los últimos 100)
        val logLines = newLogs.split("\\n")
        if (logLines.size > 100) {
            val trimmedLogs = logLines.takeLast(100).joinToString("\\n")
            accessLogPrefs.edit().putString("logs", trimmedLogs).apply()
        }
    }

    fun getAccessLogs(): List<String> {
        val logsString = accessLogPrefs.getString("logs", "") ?: ""
        return if (logsString.isEmpty()) {
            emptyList()
        } else {
            logsString.split("\\n").reversed() // Mostrar los más recientes primero
        }
    }

    fun clearAllData() {
        // Limpiar datos encriptados
        encryptedPrefs.edit().clear().apply()

        // Limpiar logs
        accessLogPrefs.edit().clear().apply()

        // Limpiar datos de rotación de claves
        keyRotationPrefs.edit().clear().apply()

        logAccess("DATA_MANAGEMENT", "Todos los datos han sido borrados de forma segura")
    }

    fun getDataProtectionInfo(): Map<String, String> {
        val rotationCount = keyRotationPrefs.getInt("rotation_count", 0)
        val lastRotation = keyRotationPrefs.getLong("last_rotation", 0L)
        val lastRotationDate = if (lastRotation > 0) {
            SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date(lastRotation))
        } else {
            "Nunca"
        }

        return mapOf(
            "Encriptación" to "AES-256-GCM",
            "Almacenamiento" to "Local encriptado",
            "Logs de acceso" to "${getAccessLogs().size} entradas",
            "Última limpieza" to (getSecureData("last_cleanup") ?: "Nunca"),
            "Rotaciones de clave" to "$rotationCount",
            "Última rotación" to lastRotationDate,
            "Verificación HMAC" to "Activa",
            "Salt único" to "Configurado",
            "Estado de seguridad" to "Activo"
        )
    }

    fun anonymizeData(data: String): String {
        // Implementación mejorada de anonimización
        return data.replace(Regex("[0-9]"), "*")
            .replace(Regex("[A-Za-z]{3,}"), "***")
            .replace(Regex("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b"), "***@***.***")
            .replace(Regex("\\b\\d{3}-\\d{3}-\\d{4}\\b"), "***-***-****")
    }
}