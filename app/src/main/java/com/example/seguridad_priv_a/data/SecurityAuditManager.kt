package com.example.seguridad_priv_a.data

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.text.SimpleDateFormat
import java.util.*
import kotlin.collections.HashMap

class SecurityAuditManager(private val context: Context) {

    private lateinit var auditPrefs: SharedPreferences
    private val accessAttempts = HashMap<String, MutableList<Long>>()
    private val rateLimitMap = HashMap<String, Long>()

    companion object {
        private const val MAX_ATTEMPTS_PER_MINUTE = 10
        private const val MAX_ATTEMPTS_PER_HOUR = 100
        private const val RATE_LIMIT_WINDOW = 60 * 1000L // 1 minuto
        private const val SUSPICIOUS_THRESHOLD = 5 // intentos en 30 segundos
        private const val ANOMALY_DETECTION_WINDOW = 30 * 1000L // 30 segundos
        private const val SIGNATURE_ALGORITHM = "SHA256withRSA"
    }

    data class AuditEvent(
        val timestamp: Long,
        val eventType: String,
        val resource: String,
        val sourceIp: String = "local",
        val userId: String = "default_user",
        val success: Boolean,
        val details: String
    )

    data class SecurityAlert(
        val timestamp: Long,
        val alertType: String,
        val severity: String,
        val description: String,
        val affectedResource: String,
        val recommendedAction: String
    )

    fun initialize() {
        auditPrefs = context.getSharedPreferences("security_audit", Context.MODE_PRIVATE)
    }

    fun recordAuditEvent(
        eventType: String,
        resource: String,
        success: Boolean,
        details: String = "",
        userId: String = "default_user"
    ) {
        val event = AuditEvent(
            timestamp = System.currentTimeMillis(),
            eventType = eventType,
            resource = resource,
            userId = userId,
            success = success,
            details = details
        )

        // Almacenar evento
        storeAuditEvent(event)

        // Detectar patrones sospechosos
        detectSuspiciousActivity(event)

        // Verificar rate limiting
        checkRateLimit(eventType, userId)
    }

    private fun storeAuditEvent(event: AuditEvent) {
        val eventJson = JSONObject().apply {
            put("timestamp", event.timestamp)
            put("eventType", event.eventType)
            put("resource", event.resource)
            put("sourceIp", event.sourceIp)
            put("userId", event.userId)
            put("success", event.success)
            put("details", event.details)
            put("hash", generateEventHash(event))
        }

        // Obtener eventos existentes
        val existingEvents = getStoredAuditEvents()
        existingEvents.put(eventJson)

        // Limitar a los últimos 1000 eventos
        if (existingEvents.length() > 1000) {
            val trimmedEvents = JSONArray()
            for (i in (existingEvents.length() - 1000) until existingEvents.length()) {
                trimmedEvents.put(existingEvents.get(i))
            }
            auditPrefs.edit().putString("audit_events", trimmedEvents.toString()).apply()
        } else {
            auditPrefs.edit().putString("audit_events", existingEvents.toString()).apply()
        }
    }

    private fun getStoredAuditEvents(): JSONArray {
        val eventsString = auditPrefs.getString("audit_events", "[]") ?: "[]"
        return JSONArray(eventsString)
    }

    private fun generateEventHash(event: AuditEvent): String {
        val eventString = "${event.timestamp}${event.eventType}${event.resource}${event.userId}${event.success}${event.details}"
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(eventString.toByteArray())
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    fun detectSuspiciousActivity(event: AuditEvent) {
        val currentTime = System.currentTimeMillis()
        val userId = event.userId

        // Obtener intentos recientes del usuario
        val userAttempts = accessAttempts.getOrPut(userId) { mutableListOf() }

        // Limpiar intentos antiguos (más de 30 segundos)
        userAttempts.removeAll { currentTime - it > ANOMALY_DETECTION_WINDOW }

        // Agregar intento actual
        userAttempts.add(currentTime)

        // Detectar patrones sospechosos
        when {
            userAttempts.size >= SUSPICIOUS_THRESHOLD -> {
                generateSecurityAlert(
                    alertType = "SUSPICIOUS_ACTIVITY",
                    severity = "HIGH",
                    description = "Múltiples intentos de acceso en corto período de tiempo",
                    affectedResource = event.resource,
                    recommendedAction = "Revisar actividad del usuario y considerar bloqueo temporal"
                )
            }

            !event.success && getRecentFailures(userId) >= 3 -> {
                generateSecurityAlert(
                    alertType = "REPEATED_FAILURES",
                    severity = "MEDIUM",
                    description = "Múltiples fallos de autenticación consecutivos",
                    affectedResource = event.resource,
                    recommendedAction = "Verificar credenciales y actividad del usuario"
                )
            }

            isUnusualTimeAccess(currentTime) -> {
                generateSecurityAlert(
                    alertType = "UNUSUAL_TIME_ACCESS",
                    severity = "LOW",
                    description = "Acceso fuera del horario habitual",
                    affectedResource = event.resource,
                    recommendedAction = "Verificar si el acceso es legítimo"
                )
            }
        }
    }

    private fun getRecentFailures(userId: String): Int {
        val events = getStoredAuditEvents()
        var failures = 0
        val cutoffTime = System.currentTimeMillis() - (5 * 60 * 1000) // Últimos 5 minutos

        for (i in 0 until events.length()) {
            val event = events.getJSONObject(i)
            if (event.getString("userId") == userId &&
                event.getLong("timestamp") > cutoffTime &&
                !event.getBoolean("success")) {
                failures++
            }
        }
        return failures
    }

    private fun isUnusualTimeAccess(timestamp: Long): Boolean {
        val calendar = Calendar.getInstance()
        calendar.timeInMillis = timestamp
        val hour = calendar.get(Calendar.HOUR_OF_DAY)

        // Considerar horario fuera de 6 AM - 10 PM como inusual
        return hour < 6 || hour > 22
    }

    fun checkRateLimit(operation: String, userId: String): Boolean {
        val currentTime = System.currentTimeMillis()
        val key = "${operation}_${userId}"

        val lastRequest = rateLimitMap[key] ?: 0L
        val timeSinceLastRequest = currentTime - lastRequest

        if (timeSinceLastRequest < RATE_LIMIT_WINDOW) {
            generateSecurityAlert(
                alertType = "RATE_LIMIT_EXCEEDED",
                severity = "MEDIUM",
                description = "Usuario excedió el límite de solicitudes por minuto",
                affectedResource = operation,
                recommendedAction = "Aplicar throttling temporal al usuario"
            )
            return false
        }

        rateLimitMap[key] = currentTime
        return true
    }

    fun isRateLimited(operation: String, userId: String): Boolean {
        val currentTime = System.currentTimeMillis()
        val key = "${operation}_${userId}"
        val lastRequest = rateLimitMap[key] ?: 0L

        return (currentTime - lastRequest) < RATE_LIMIT_WINDOW
    }

    private fun generateSecurityAlert(
        alertType: String,
        severity: String,
        description: String,
        affectedResource: String,
        recommendedAction: String
    ) {
        val alert = SecurityAlert(
            timestamp = System.currentTimeMillis(),
            alertType = alertType,
            severity = severity,
            description = description,
            affectedResource = affectedResource,
            recommendedAction = recommendedAction
        )

        storeSecurityAlert(alert)
    }

    private fun storeSecurityAlert(alert: SecurityAlert) {
        val alertJson = JSONObject().apply {
            put("timestamp", alert.timestamp)
            put("alertType", alert.alertType)
            put("severity", alert.severity)
            put("description", alert.description)
            put("affectedResource", alert.affectedResource)
            put("recommendedAction", alert.recommendedAction)
        }

        val existingAlerts = getStoredSecurityAlerts()
        existingAlerts.put(alertJson)

        // Limitar a las últimas 500 alertas
        if (existingAlerts.length() > 500) {
            val trimmedAlerts = JSONArray()
            for (i in (existingAlerts.length() - 500) until existingAlerts.length()) {
                trimmedAlerts.put(existingAlerts.get(i))
            }
            auditPrefs.edit().putString("security_alerts", trimmedAlerts.toString()).apply()
        } else {
            auditPrefs.edit().putString("security_alerts", existingAlerts.toString()).apply()
        }
    }

    fun getStoredSecurityAlerts(): JSONArray {
        val alertsString = auditPrefs.getString("security_alerts", "[]") ?: "[]"
        return JSONArray(alertsString)
    }

    fun getSecurityAlerts(): List<SecurityAlert> {
        val alerts = mutableListOf<SecurityAlert>()
        val jsonAlerts = getStoredSecurityAlerts()

        for (i in 0 until jsonAlerts.length()) {
            val alertJson = jsonAlerts.getJSONObject(i)
            alerts.add(
                SecurityAlert(
                    timestamp = alertJson.getLong("timestamp"),
                    alertType = alertJson.getString("alertType"),
                    severity = alertJson.getString("severity"),
                    description = alertJson.getString("description"),
                    affectedResource = alertJson.getString("affectedResource"),
                    recommendedAction = alertJson.getString("recommendedAction")
                )
            )
        }

        return alerts.sortedByDescending { it.timestamp }
    }

    fun exportAuditLogs(): String {
        val exportData = JSONObject().apply {
            put("exportTimestamp", System.currentTimeMillis())
            put("exportFormat", "Security Audit Export v1.0")
            put("events", getStoredAuditEvents())
            put("alerts", getStoredSecurityAlerts())
            put("metadata", JSONObject().apply {
                put("totalEvents", getStoredAuditEvents().length())
                put("totalAlerts", getStoredSecurityAlerts().length())
                put("exportedBy", "SecurityAuditManager")
            })
        }

        // Generar firma digital del export
        val signature = generateDigitalSignature(exportData.toString())
        exportData.put("digitalSignature", signature)

        return exportData.toString(2) // Pretty print with 2-space indentation
    }

    private fun generateDigitalSignature(data: String): String {
        return try {
            // En un entorno real, usarías una clave privada real
            // Por ahora, generamos un hash como "firma"
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(data.toByteArray())
            Base64.encodeToString(hash, Base64.NO_WRAP)
        } catch (e: Exception) {
            "SIGNATURE_ERROR: ${e.message}"
        }
    }

    fun getAuditStatistics(): Map<String, Any> {
        val events = getStoredAuditEvents()
        val alerts = getStoredSecurityAlerts()
        val currentTime = System.currentTimeMillis()

        // Contar eventos por tipo en las últimas 24 horas
        val eventCounts = mutableMapOf<String, Int>()
        val alertCounts = mutableMapOf<String, Int>()
        val last24Hours = currentTime - (24 * 60 * 60 * 1000)

        for (i in 0 until events.length()) {
            val event = events.getJSONObject(i)
            if (event.getLong("timestamp") > last24Hours) {
                val eventType = event.getString("eventType")
                eventCounts[eventType] = eventCounts.getOrDefault(eventType, 0) + 1
            }
        }

        for (i in 0 until alerts.length()) {
            val alert = alerts.getJSONObject(i)
            if (alert.getLong("timestamp") > last24Hours) {
                val alertType = alert.getString("alertType")
                alertCounts[alertType] = alertCounts.getOrDefault(alertType, 0) + 1
            }
        }

        return mapOf(
            "totalEvents" to events.length(),
            "totalAlerts" to alerts.length(),
            "eventsLast24h" to eventCounts.values.sum(),
            "alertsLast24h" to alertCounts.values.sum(),
            "eventsByType" to eventCounts,
            "alertsByType" to alertCounts,
            "lastEventTime" to if (events.length() > 0) events.getJSONObject(events.length() - 1).getLong("timestamp") else 0L,
            "lastAlertTime" to if (alerts.length() > 0) alerts.getJSONObject(alerts.length() - 1).getLong("timestamp") else 0L
        )
    }

    fun clearAuditData() {
        auditPrefs.edit().clear().apply()
        accessAttempts.clear()
        rateLimitMap.clear()
    }
}