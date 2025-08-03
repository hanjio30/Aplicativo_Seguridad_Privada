package com.example.seguridad_priv_a

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.example.seguridad_priv_a.databinding.ActivityDataProtectionBinding
import com.example.seguridad_priv_a.data.SecurityAuditManager
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.Executor

class DataProtectionActivity : AppCompatActivity() {

    private lateinit var binding: ActivityDataProtectionBinding
    private val dataProtectionManager by lazy {
        (application as PermissionsApplication).dataProtectionManager
    }
    private val securityAuditManager by lazy {
        SecurityAuditManager(this).apply { initialize() }
    }

    private lateinit var executor: Executor
    private lateinit var biometricPrompt: BiometricPrompt
    private lateinit var promptInfo: BiometricPrompt.PromptInfo

    private var sessionStartTime: Long = 0
    private var isAuthenticated = false
    private val sessionTimeoutHandler = Handler(Looper.getMainLooper())
    private val sessionTimeoutRunnable = Runnable {
        handleSessionTimeout()
    }

    companion object {
        private const val SESSION_TIMEOUT_MS = 5 * 60 * 1000L // 5 minutos
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityDataProtectionBinding.inflate(layoutInflater)
        setContentView(binding.root)

        setupBiometricAuthentication()
        setupUI()

        // Requerir autenticación para acceder
        requestAuthentication()

        dataProtectionManager.logAccess("NAVIGATION", "DataProtectionActivity abierta")
        securityAuditManager.recordAuditEvent(
            eventType = "ACTIVITY_ACCESS",
            resource = "DataProtectionActivity",
            success = true,
            details = "Usuario accedió a la actividad de protección de datos"
        )
    }

    private fun setupBiometricAuthentication() {
        executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(
            this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    securityAuditManager.recordAuditEvent(
                        eventType = "BIOMETRIC_AUTH",
                        resource = "DataProtectionActivity",
                        success = false,
                        details = "Error de autenticación: $errString"
                    )
                    handleAuthenticationFailure("Error de autenticación: $errString")
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    securityAuditManager.recordAuditEvent(
                        eventType = "BIOMETRIC_AUTH",
                        resource = "DataProtectionActivity",
                        success = true,
                        details = "Autenticación biométrica exitosa"
                    )
                    handleAuthenticationSuccess()
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    securityAuditManager.recordAuditEvent(
                        eventType = "BIOMETRIC_AUTH",
                        resource = "DataProtectionActivity",
                        success = false,
                        details = "Fallo en autenticación biométrica"
                    )
                    Toast.makeText(
                        this@DataProtectionActivity,
                        "Autenticación fallida",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            })

        promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Autenticación Requerida")
            .setSubtitle("Usa tu huella dactilar o reconocimiento facial para acceder")
            .setNegativeButtonText("Usar PIN/Patrón")
            .build()
    }

    private fun requestAuthentication() {
        when (BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                biometricPrompt.authenticate(promptInfo)
            }

            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                showFallbackAuthenticationDialog()
            }

            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                showFallbackAuthenticationDialog()
            }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                showBiometricSetupDialog()
            }

            else -> {
                showFallbackAuthenticationDialog()
            }
        }
    }

    private fun showBiometricSetupDialog() {
        AlertDialog.Builder(this)
            .setTitle("Configurar Biometría")
            .setMessage("No tienes configurada la autenticación biométrica. ¿Deseas configurarla ahora?")
            .setPositiveButton("Configurar") { _, _ ->
                val enrollIntent = Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                    putExtra(
                        Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                    )
                }
                startActivity(enrollIntent)
            }
            .setNegativeButton("Usar PIN/Patrón") { _, _ ->
                showFallbackAuthenticationDialog()
            }
            .setCancelable(false)
            .show()
    }

    private fun showFallbackAuthenticationDialog() {
        // Simulación de autenticación con PIN/Patrón
        AlertDialog.Builder(this)
            .setTitle("Autenticación con PIN")
            .setMessage("Ingresa tu PIN de seguridad:")
            .setView(android.widget.EditText(this).apply {
                inputType =
                    android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            })
            .setPositiveButton("Autenticar") { dialog, _ ->
                val editText =
                    (dialog as AlertDialog).findViewById<android.widget.EditText>(android.R.id.edit)
                val pin = editText?.text?.toString()

                if (validatePin(pin)) {
                    securityAuditManager.recordAuditEvent(
                        eventType = "PIN_AUTH",
                        resource = "DataProtectionActivity",
                        success = true,
                        details = "Autenticación con PIN exitosa"
                    )
                    handleAuthenticationSuccess()
                } else {
                    securityAuditManager.recordAuditEvent(
                        eventType = "PIN_AUTH",
                        resource = "DataProtectionActivity",
                        success = false,
                        details = "PIN incorrecto"
                    )
                    handleAuthenticationFailure("PIN incorrecto")
                }
            }
            .setNegativeButton("Cancelar") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    private fun validatePin(pin: String?): Boolean {
        // Simulación de validación de PIN
        // En un caso real, esto estaría almacenado de forma segura
        return pin == "1234" // PIN de ejemplo
    }

    private fun handleAuthenticationSuccess() {
        isAuthenticated = true
        sessionStartTime = System.currentTimeMillis()
        startSessionTimeout()

        loadDataProtectionInfo()
        loadAccessLogs()
        loadSecurityAlerts()

        Toast.makeText(this, "Autenticación exitosa", Toast.LENGTH_SHORT).show()
    }

    private fun handleAuthenticationFailure(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        finish()
    }

    private fun startSessionTimeout() {
        sessionTimeoutHandler.removeCallbacks(sessionTimeoutRunnable)
        sessionTimeoutHandler.postDelayed(sessionTimeoutRunnable, SESSION_TIMEOUT_MS)
    }

    private fun resetSessionTimeout() {
        if (isAuthenticated) {
            startSessionTimeout()
        }
    }

    private fun handleSessionTimeout() {
        isAuthenticated = false
        securityAuditManager.recordAuditEvent(
            eventType = "SESSION_TIMEOUT",
            resource = "DataProtectionActivity",
            success = true,
            details = "Sesión expirada por inactividad"
        )

        AlertDialog.Builder(this)
            .setTitle("Sesión Expirada")
            .setMessage("Tu sesión ha expirado por inactividad. Debes autenticarte nuevamente.")
            .setPositiveButton("Autenticar") { _, _ ->
                requestAuthentication()
            }
            .setNegativeButton("Salir") { _, _ ->
                finish()
            }
            .setCancelable(false)
            .show()
    }

    private fun setupUI() {
        binding.btnViewLogs.setOnClickListener {
            if (checkAuthentication()) {
                loadAccessLogs()
                resetSessionTimeout()
                Toast.makeText(this, "Logs actualizados", Toast.LENGTH_SHORT).show()
            }
        }

        binding.btnClearData.setOnClickListener {
            if (checkAuthentication()) {
                showClearDataDialog()
                resetSessionTimeout()
            }
        }

        // Nuevo botón para exportar logs de auditoría
        binding.btnExportAudit?.setOnClickListener {
            if (checkAuthentication()) {
                exportAuditLogs()
                resetSessionTimeout()
            }
        }

        // Nuevo botón para ver alertas de seguridad
        binding.btnViewAlerts?.setOnClickListener {
            if (checkAuthentication()) {
                showSecurityAlertsDialog()
                resetSessionTimeout()
            }
        }
    }

    private fun checkAuthentication(): Boolean {
        if (!isAuthenticated) {
            requestAuthentication()
            return false
        }
        return true
    }

    private fun loadDataProtectionInfo() {
        val info = dataProtectionManager.getDataProtectionInfo()
        val auditStats = securityAuditManager.getAuditStatistics()
        val infoText = StringBuilder()

        infoText.append("🔐 INFORMACIÓN DE SEGURIDAD\n\n")
        info.forEach { (key, value) ->
            infoText.append("• $key: $value\n")
        }

        infoText.append("\n📊 ESTADÍSTICAS DE AUDITORÍA:\n")
        infoText.append("• Total eventos: ${auditStats["totalEvents"]}\n")
        infoText.append("• Total alertas: ${auditStats["totalAlerts"]}\n")
        infoText.append("• Eventos (24h): ${auditStats["eventsLast24h"]}\n")
        infoText.append("• Alertas (24h): ${auditStats["alertsLast24h"]}\n")

        infoText.append("\n🛡️ EVIDENCIAS DE PROTECCIÓN:\n")
        infoText.append("• Encriptación AES-256-GCM activa\n")
        infoText.append("• Rotación automática de claves\n")
        infoText.append("• Verificación HMAC de integridad\n")
        infoText.append("• Auditoría de seguridad activa\n")
        infoText.append("• Detección de anomalías\n")
        infoText.append("• Rate limiting implementado\n")
        infoText.append("• Autenticación biométrica\n")
        infoText.append("• Timeout de sesión (5 min)\n")
        infoText.append("• No hay compartición de datos\n")

        binding.tvDataProtectionInfo.text = infoText.toString()

        dataProtectionManager.logAccess("DATA_PROTECTION", "Información de protección mostrada")
        securityAuditManager.recordAuditEvent(
            eventType = "DATA_VIEW",
            resource = "ProtectionInfo",
            success = true,
            details = "Usuario consultó información de protección"
        )
    }

    private fun loadAccessLogs() {
        val logs = dataProtectionManager.getAccessLogs()

        if (logs.isNotEmpty()) {
            val logsText = logs.take(50).joinToString("\n") // Mostrar solo los últimos 50 logs
            binding.tvAccessLogs.text = logsText
        } else {
            binding.tvAccessLogs.text = "No hay logs disponibles"
        }

        dataProtectionManager.logAccess("DATA_ACCESS", "Logs de acceso consultados")
        securityAuditManager.recordAuditEvent(
            eventType = "LOGS_VIEW",
            resource = "AccessLogs",
            success = true,
            details = "Usuario consultó logs de acceso"
        )
    }

    private fun loadSecurityAlerts() {
        val alerts = securityAuditManager.getSecurityAlerts()

        if (alerts.isNotEmpty()) {
            val alertsText = StringBuilder()
            alertsText.append("🚨 ALERTAS DE SEGURIDAD:\n\n")

            alerts.take(10).forEach { alert ->
                val time = SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss",
                    Locale.getDefault()
                ).format(Date(alert.timestamp))
                alertsText.append("[$time] ${alert.severity}\n")
                alertsText.append("Tipo: ${alert.alertType}\n")
                alertsText.append("Descripción: ${alert.description}\n")
                alertsText.append("Recurso: ${alert.affectedResource}\n")
                alertsText.append("Acción recomendada: ${alert.recommendedAction}\n\n")
            }

            binding.tvSecurityAlerts?.text = alertsText.toString()
        }
    }

    private fun showSecurityAlertsDialog() {
        val alerts = securityAuditManager.getSecurityAlerts()

        if (alerts.isEmpty()) {
            Toast.makeText(this, "No hay alertas de seguridad", Toast.LENGTH_SHORT).show()
            return
        }

        val alertsText = StringBuilder()
        alerts.take(20).forEach { alert ->
            val time =
                SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date(alert.timestamp))
            alertsText.append("[$time] ${alert.severity} - ${alert.alertType}\n")
            alertsText.append("${alert.description}\n\n")
        }

        AlertDialog.Builder(this)
            .setTitle("Alertas de Seguridad")
            .setMessage(alertsText.toString())
            .setPositiveButton("Cerrar", null)
            .setNeutralButton("Limpiar Alertas") { _, _ ->
                clearSecurityAlerts()
            }
            .show()

        securityAuditManager.recordAuditEvent(
            eventType = "ALERTS_VIEW",
            resource = "SecurityAlerts",
            success = true,
            details = "Usuario consultó alertas de seguridad"
        )
    }

    private fun clearSecurityAlerts() {
        AlertDialog.Builder(this)
            .setTitle("Limpiar Alertas")
            .setMessage("¿Estás seguro de que deseas limpiar todas las alertas de seguridad?")
            .setPositiveButton("Limpiar") { _, _ ->
                securityAuditManager.clearAuditData()
                Toast.makeText(this, "Alertas de seguridad limpiadas", Toast.LENGTH_SHORT).show()
                loadSecurityAlerts()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun exportAuditLogs() {
        try {
            val exportData = securityAuditManager.exportAuditLogs()

            // En un caso real, guardarías esto en un archivo o lo compartirías
            Toast.makeText(this, "Logs de auditoría exportados exitosamente", Toast.LENGTH_LONG)
                .show()

            // Mostrar preview de los datos exportados
            AlertDialog.Builder(this)
                .setTitle("Export de Auditoría")
                .setMessage("Datos exportados exitosamente.\n\nTamaño: ${exportData.length} caracteres\nIncluye firma digital para verificación de integridad.")
                .setPositiveButton("Cerrar", null)
                .show()

            securityAuditManager.recordAuditEvent(
                eventType = "AUDIT_EXPORT",
                resource = "AuditLogs",
                success = true,
                details = "Usuario exportó logs de auditoría"
            )

        } catch (e: Exception) {
            Toast.makeText(this, "Error al exportar logs: ${e.message}", Toast.LENGTH_LONG).show()
            securityAuditManager.recordAuditEvent(
                eventType = "AUDIT_EXPORT",
                resource = "AuditLogs",
                success = false,
                details = "Error al exportar: ${e.message}"
            )
        }
    }

    private fun showClearDataDialog() {
        AlertDialog.Builder(this)
            .setTitle("Borrar Todos los Datos")
            .setMessage("¿Estás seguro de que deseas borrar todos los datos almacenados, logs de acceso y datos de auditoría? Esta acción no se puede deshacer.")
            .setPositiveButton("Borrar") { _, _ ->
                clearAllData()
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun clearAllData() {
        dataProtectionManager.clearAllData()
        securityAuditManager.clearAuditData()

        // Actualizar UI
        binding.tvAccessLogs.text = "Todos los datos han sido borrados"
        binding.tvDataProtectionInfo.text =
            "🔐 DATOS BORRADOS DE FORMA SEGURA\n\nTodos los datos personales, logs y datos de auditoría han sido eliminados del dispositivo."
        binding.tvSecurityAlerts?.text = "Alertas de seguridad limpiadas"

        Toast.makeText(this, "Datos borrados de forma segura", Toast.LENGTH_LONG).show()

        // Este log se creará después del borrado
        dataProtectionManager.logAccess(
            "DATA_MANAGEMENT",
            "Todos los datos borrados por el usuario"
        )
        securityAuditManager.recordAuditEvent(
            eventType = "DATA_CLEANUP",
            resource = "AllData",
            success = true,
            details = "Usuario eliminó todos los datos del sistema"
        )
    }

    override fun onResume() {
        super.onResume()
        if (isAuthenticated) {
            loadAccessLogs()
            loadSecurityAlerts()
            resetSessionTimeout()
        }
    }

    override fun onPause() {
        super.onPause()
        sessionTimeoutHandler.removeCallbacks(sessionTimeoutRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        sessionTimeoutHandler.removeCallbacks(sessionTimeoutRunnable)
    }

    override fun onUserInteraction() {
        super.onUserInteraction()
        resetSessionTimeout()
    }
}