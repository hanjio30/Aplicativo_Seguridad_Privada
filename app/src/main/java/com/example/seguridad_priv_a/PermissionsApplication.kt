package com.example.seguridad_priv_a

import android.app.Application
import com.example.seguridad_priv_a.data.DataProtectionManager
import com.example.seguridad_priv_a.data.SecurityAuditManager

class PermissionsApplication : Application() {

    lateinit var dataProtectionManager: DataProtectionManager
        private set

    lateinit var securityAuditManager: SecurityAuditManager
        private set

    override fun onCreate() {
        super.onCreate()

        // Inicializar gestores de seguridad
        dataProtectionManager = DataProtectionManager(this)
        securityAuditManager = SecurityAuditManager(this)

        // Inicializar componentes
        dataProtectionManager.initialize()
        securityAuditManager.initialize()

        // Registrar inicio de aplicación
        securityAuditManager.recordAuditEvent(
            eventType = "APPLICATION_START",
            resource = "PermissionsApplication",
            success = true,
            details = "Aplicación iniciada correctamente"
        )

        dataProtectionManager.logAccess("APPLICATION", "Aplicación iniciada")
    }

    override fun onTerminate() {
        super.onTerminate()

        // Registrar cierre de aplicación
        securityAuditManager.recordAuditEvent(
            eventType = "APPLICATION_TERMINATE",
            resource = "PermissionsApplication",
            success = true,
            details = "Aplicación terminada"
        )

        dataProtectionManager.logAccess("APPLICATION", "Aplicación terminada")
    }
}