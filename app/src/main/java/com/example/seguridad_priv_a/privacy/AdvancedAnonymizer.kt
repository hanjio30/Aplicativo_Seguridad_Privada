package com.example.seguridad_priv_a.privacy

import android.content.Context
import com.example.seguridad_priv_a.security.AntiTamperingManager
import kotlinx.coroutines.*
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.*
import kotlin.math.*
import kotlin.random.Random

/**
 * Advanced Anonymization Framework
 * Implementa k-anonymity, l-diversity, differential privacy y data masking avanzado
 */
class AdvancedAnonymizer(private val context: Context) {

    private val random = SecureRandom()
    private val maskingPolicies = mutableMapOf<String, MaskingPolicy>()
    private val retentionPolicies = mutableMapOf<String, RetentionPolicy>()

    companion object {
        private const val DEFAULT_K = 5
        private const val DEFAULT_L = 3
        private const val DEFAULT_EPSILON = 1.0
        private const val HASH_ALGORITHM = "SHA-256"
    }

    data class PersonalData(
        val id: String,
        val quasiIdentifiers: Map<String, Any>, // Edad, código postal, etc.
        val sensitiveAttributes: Map<String, Any>, // Datos médicos, ingresos, etc.
        val identifiers: Map<String, Any>, // Nombre, email, etc.
        val dataType: DataType,
        val timestamp: Long = System.currentTimeMillis()
    )

    data class AnonymizedData(
        val anonymizedId: String,
        val generalizedQuasiIdentifiers: Map<String, Any>,
        val suppressedSensitiveAttributes: Map<String, Any>,
        val anonymizationMethod: String,
        val privacyLevel: PrivacyLevel,
        val metadata: AnonymizationMetadata
    )

    data class NumericData(
        val value: Double,
        val range: Pair<Double, Double>,
        val precision: Int = 2
    )

    data class MaskingPolicy(
        val dataType: DataType,
        val maskingMethod: MaskingMethod,
        val preserveLength: Boolean = true,
        val preserveFormat: Boolean = true,
        val customPattern: String? = null,
        val strength: MaskingStrength = MaskingStrength.MEDIUM
    )

    data class RetentionPolicy(
        val dataType: DataType,
        val retentionPeriodMs: Long,
        val automaticDeletion: Boolean = true,
        val anonymizationAfterExpiry: Boolean = true,
        val complianceStandard: ComplianceStandard
    )

    data class AnonymizationMetadata(
        val originalDataHash: String,
        val anonymizationTimestamp: Long,
        val method: String,
        val parameters: Map<String, Any>,
        val privacyBudgetUsed: Double = 0.0,
        val retentionExpiry: Long? = null
    )

    enum class DataType {
        PERSONAL_IDENTIFIER, EMAIL, PHONE, ADDRESS, NUMERIC,
        DATE, MEDICAL, FINANCIAL, BIOMETRIC, LOCATION, CUSTOM
    }

    enum class MaskingMethod {
        HASH, TOKENIZE, GENERALIZE, SUPPRESS, PSEUDONYMIZE,
        PARTIAL_MASK, NOISE_ADDITION, FORMAT_PRESERVING
    }

    enum class MaskingStrength { LOW, MEDIUM, HIGH, MAXIMUM }

    enum class PrivacyLevel { BASIC, ENHANCED, MAXIMUM }

    enum class ComplianceStandard { GDPR, CCPA, HIPAA, CUSTOM }

    fun initialize() {
        setupDefaultMaskingPolicies()
        setupDefaultRetentionPolicies()
    }

    private fun setupDefaultMaskingPolicies() {
        maskingPolicies[DataType.EMAIL.name] = MaskingPolicy(
            dataType = DataType.EMAIL,
            maskingMethod = MaskingMethod.PARTIAL_MASK,
            customPattern = "***@***.***"
        )

        maskingPolicies[DataType.PHONE.name] = MaskingPolicy(
            dataType = DataType.PHONE,
            maskingMethod = MaskingMethod.PARTIAL_MASK,
            customPattern = "***-***-****"
        )

        maskingPolicies[DataType.PERSONAL_IDENTIFIER.name] = MaskingPolicy(
            dataType = DataType.PERSONAL_IDENTIFIER,
            maskingMethod = MaskingMethod.HASH,
            strength = MaskingStrength.MAXIMUM
        )

        maskingPolicies[DataType.FINANCIAL.name] = MaskingPolicy(
            dataType = DataType.FINANCIAL,
            maskingMethod = MaskingMethod.TOKENIZE,
            strength = MaskingStrength.HIGH
        )
    }

    private fun setupDefaultRetentionPolicies() {
        retentionPolicies[DataType.PERSONAL_IDENTIFIER.name] = RetentionPolicy(
            dataType = DataType.PERSONAL_IDENTIFIER,
            retentionPeriodMs = 365L * 24 * 60 * 60 * 1000, // 1 año
            complianceStandard = ComplianceStandard.GDPR
        )

        retentionPolicies[DataType.MEDICAL.name] = RetentionPolicy(
            dataType = DataType.MEDICAL,
            retentionPeriodMs = 7L * 365 * 24 * 60 * 60 * 1000, // 7 años
            complianceStandard = ComplianceStandard.HIPAA
        )
    }

    /**
     * Implementación de k-anonymity
     * Asegura que cada registro sea indistinguible de al menos k-1 otros registros
     */
    suspend fun anonymizeWithKAnonymity(
        data: List<PersonalData>,
        k: Int = DEFAULT_K
    ): List<AnonymizedData> = withContext(Dispatchers.Default) {

        if (data.isEmpty() || k <= 1) return@withContext emptyList()

        val result = mutableListOf<AnonymizedData>()

        // Agrupar datos por quasi-identifiers similares
        val groups = groupByQuasiIdentifiers(data, k)

        groups.forEach { group ->
            if (group.size >= k) {
                // Generalizar quasi-identifiers del grupo
                val generalizedQuasiIds = generalizeQuasiIdentifiers(group)

                group.forEach { originalData ->
                    val anonymized = AnonymizedData(
                        anonymizedId = generateAnonymousId(),
                        generalizedQuasiIdentifiers = generalizedQuasiIds,
                        suppressedSensitiveAttributes = originalData.sensitiveAttributes,
                        anonymizationMethod = "k-anonymity (k=$k)",
                        privacyLevel = PrivacyLevel.ENHANCED,
                        metadata = AnonymizationMetadata(
                            originalDataHash = hashData(originalData),
                            anonymizationTimestamp = System.currentTimeMillis(),
                            method = "k-anonymity",
                            parameters = mapOf("k" to k)
                        )
                    )
                    result.add(anonymized)
                }
            }
        }

        result
    }

    /**
     * Implementación de l-diversity
     * Asegura que cada grupo tenga al menos l valores distintos para atributos sensibles
     */
    suspend fun anonymizeWithLDiversity(
        data: List<PersonalData>,
        k: Int = DEFAULT_K,
        l: Int = DEFAULT_L
    ): List<AnonymizedData> = withContext(Dispatchers.Default) {

        // Primero aplicar k-anonymity
        val kAnonymizedGroups = groupByQuasiIdentifiers(data, k)
        val result = mutableListOf<AnonymizedData>()

        kAnonymizedGroups.forEach { group ->
            if (group.size >= k && satisfiesLDiversity(group, l)) {
                val generalizedQuasiIds = generalizeQuasiIdentifiers(group)
                val diversifiedSensitiveAttrs = diversifySensitiveAttributes(group, l)

                group.forEachIndexed { index, originalData ->
                    val anonymized = AnonymizedData(
                        anonymizedId = generateAnonymousId(),
                        generalizedQuasiIdentifiers = generalizedQuasiIds,
                        suppressedSensitiveAttributes = diversifiedSensitiveAttrs[index],
                        anonymizationMethod = "l-diversity (k=$k, l=$l)",
                        privacyLevel = PrivacyLevel.MAXIMUM,
                        metadata = AnonymizationMetadata(
                            originalDataHash = hashData(originalData),
                            anonymizationTimestamp = System.currentTimeMillis(),
                            method = "l-diversity",
                            parameters = mapOf("k" to k, "l" to l)
                        )
                    )
                    result.add(anonymized)
                }
            }
        }

        result
    }

    /**
     * Implementación de Differential Privacy
     * Añade ruido calibrado para preservar privacidad mientras mantiene utilidad
     */
    fun applyDifferentialPrivacy(
        data: NumericData,
        epsilon: Double = DEFAULT_EPSILON
    ): NumericData {
        // Calcular sensibilidad de la consulta
        val sensitivity = calculateSensitivity(data.range)

        // Generar ruido Laplace
        val noise = generateLaplaceNoise(sensitivity / epsilon)

        // Aplicar ruido y ajustar al rango válido
        val noisyValue = (data.value + noise).coerceIn(data.range.first, data.range.second)

        return NumericData(
            value = Math.round(noisyValue * 10.0.pow(data.precision)) / 10.0.pow(data.precision),
            range = data.range,
            precision = data.precision
        )
    }

    /**
     * Sistema de masking específico por tipo de dato
     */
    fun maskByDataType(data: Any, dataType: DataType): Any {
        val policy = maskingPolicies[dataType.name] ?: getDefaultMaskingPolicy(dataType)
        return applyMaskingPolicy(data, policy)
    }

    private fun applyMaskingPolicy(data: Any, policy: MaskingPolicy): Any {
        return when (policy.maskingMethod) {
            MaskingMethod.HASH -> hashValue(data.toString())
            MaskingMethod.TOKENIZE -> tokenizeValue(data.toString())
            MaskingMethod.GENERALIZE -> generalizeValue(data, policy.dataType)
            MaskingMethod.SUPPRESS -> suppressValue(data, policy.strength)
            MaskingMethod.PSEUDONYMIZE -> pseudonymizeValue(data.toString())
            MaskingMethod.PARTIAL_MASK -> partialMask(data.toString(), policy)
            MaskingMethod.NOISE_ADDITION -> addNoise(data)
            MaskingMethod.FORMAT_PRESERVING -> formatPreservingMask(data.toString(), policy)
        }
    }

    private fun hashValue(value: String): String {
        return try {
            val digest = java.security.MessageDigest.getInstance(HASH_ALGORITHM)
            val salt = generateSalt()
            val saltedValue = "$value$salt"
            val hash = digest.digest(saltedValue.toByteArray())
            android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            "***HASHED***"
        }
    }

    private fun tokenizeValue(value: String): String {
        // Generar token único pero consistente para el mismo valor
        val hash = hashValue(value).take(8)
        return "TOKEN_$hash"
    }

    private fun generalizeValue(data: Any, dataType: DataType): Any {
        return when (dataType) {
            DataType.NUMERIC -> {
                val num = data.toString().toDoubleOrNull() ?: return "***"
                val range = getRangeForValue(num)
                "${range.first.toInt()}-${range.second.toInt()}"
            }
            DataType.DATE -> {
                try {
                    val date = SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).parse(data.toString())
                    val cal = Calendar.getInstance().apply { time = date }
                    "${cal.get(Calendar.YEAR)}-Q${(cal.get(Calendar.MONTH) / 3) + 1}"
                } catch (e: Exception) {
                    "20XX-QX"
                }
            }
            DataType.ADDRESS -> {
                // Generalizar a ciudad o región
                val parts = data.toString().split(",")
                if (parts.size >= 2) "${parts.last().trim()}" else "***"
            }
            else -> "***"
        }
    }

    private fun suppressValue(data: Any, strength: MaskingStrength): String {
        val value = data.toString()
        return when (strength) {
            MaskingStrength.LOW -> value.take(2) + "*".repeat(maxOf(0, value.length - 2))
            MaskingStrength.MEDIUM -> "*".repeat(value.length)
            MaskingStrength.HIGH -> "***"
            MaskingStrength.MAXIMUM -> ""
        }
    }

    private fun pseudonymizeValue(value: String): String {
        // Crear pseudónimo consistente pero no reversible
        val hash = hashValue(value)
        val names = listOf("Alex", "Jordan", "Taylor", "Casey", "Riley", "Morgan", "Avery", "Quinn")
        val index = hash.hashCode().absoluteValue % names.size
        return "${names[index]}_${hash.take(4)}"
    }

    private fun partialMask(value: String, policy: MaskingPolicy): String {
        val pattern = policy.customPattern ?: return suppressValue(value, policy.strength)

        return when (policy.dataType) {
            DataType.EMAIL -> {
                val parts = value.split("@")
                if (parts.size == 2) {
                    val username = parts[0].take(1) + "*".repeat(maxOf(0, parts[0].length - 1))
                    val domain = parts[1].split(".").let { domainParts ->
                        if (domainParts.size >= 2) {
                            "*".repeat(domainParts[0].length) + "." + domainParts.last()
                        } else "***.***"
                    }
                    "$username@$domain"
                } else pattern
            }
            DataType.PHONE -> {
                if (value.length >= 10) {
                    val formatted = value.replace(Regex("[^0-9]"), "")
                    "***-***-${formatted.takeLast(4)}"
                } else pattern
            }
            else -> pattern
        }
    }

    private fun addNoise(data: Any): Any {
        return when (data) {
            is Number -> {
                val noise = random.nextGaussian() * (data.toDouble() * 0.1)
                data.toDouble() + noise
            }
            else -> data
        }
    }

    private fun formatPreservingMask(value: String, policy: MaskingPolicy): String {
        // Preservar formato pero cambiar contenido
        return value.map { char ->
            when {
                char.isDigit() -> Random.nextInt(0, 10).toString().first()
                char.isLetter() -> if (char.isUpperCase()) {
                    ('A'..'Z').random()
                } else {
                    ('a'..'z').random()
                }
                else -> char // Preservar caracteres especiales
            }
        }.joinToString("")
    }

    /**
     * Gestión de políticas de retención configurables
     */
    fun applyRetentionPolicy(data: PersonalData): RetentionAction {
        val policy = retentionPolicies[data.dataType.name] ?: return RetentionAction.KEEP

        val dataAge = System.currentTimeMillis() - data.timestamp

        return when {
            dataAge > policy.retentionPeriodMs -> {
                if (policy.automaticDeletion) {
                    RetentionAction.DELETE
                } else if (policy.anonymizationAfterExpiry) {
                    RetentionAction.ANONYMIZE
                } else {
                    RetentionAction.REVIEW
                }
            }
            dataAge > (policy.retentionPeriodMs * 0.8) -> RetentionAction.WARN
            else -> RetentionAction.KEEP
        }
    }

    enum class RetentionAction { KEEP, WARN, ANONYMIZE, DELETE, REVIEW }

    /**
     * Procesamiento en lote con diferentes niveles de privacidad
     */
    suspend fun anonymizeBatch(
        data: List<PersonalData>,
        privacyLevel: PrivacyLevel = PrivacyLevel.ENHANCED
    ): List<AnonymizedData> = withContext(Dispatchers.Default) {

        when (privacyLevel) {
            PrivacyLevel.BASIC -> {
                data.map { personalData ->
                    anonymizeBasic(personalData)
                }
            }
            PrivacyLevel.ENHANCED -> {
                anonymizeWithKAnonymity(data, k = 5)
            }
            PrivacyLevel.MAXIMUM -> {
                anonymizeWithLDiversity(data, k = 5, l = 3)
            }
        }
    }

    private fun anonymizeBasic(data: PersonalData): AnonymizedData {
        val maskedQuasiIds = data.quasiIdentifiers.mapValues { (key, value) ->
            val dataType = inferDataType(key, value)
            maskByDataType(value, dataType)
        }

        val maskedSensitive = data.sensitiveAttributes.mapValues { (key, value) ->
            val dataType = inferDataType(key, value)
            maskByDataType(value, dataType)
        }

        return AnonymizedData(
            anonymizedId = generateAnonymousId(),
            generalizedQuasiIdentifiers = maskedQuasiIds,
            suppressedSensitiveAttributes = maskedSensitive,
            anonymizationMethod = "basic-masking",
            privacyLevel = PrivacyLevel.BASIC,
            metadata = AnonymizationMetadata(
                originalDataHash = hashData(data),
                anonymizationTimestamp = System.currentTimeMillis(),
                method = "basic",
                parameters = emptyMap()
            )
        )
    }

    /**
     * Funciones auxiliares para k-anonymity y l-diversity
     */
    private fun groupByQuasiIdentifiers(data: List<PersonalData>, k: Int): List<List<PersonalData>> {
        // Agrupar por quasi-identifiers similares
        val groups = mutableMapOf<String, MutableList<PersonalData>>()

        data.forEach { record ->
            val groupKey = generateGroupKey(record.quasiIdentifiers)
            groups.getOrPut(groupKey) { mutableListOf() }.add(record)
        }

        // Filtrar grupos que cumplan con k-anonymity
        return groups.values.filter { it.size >= k }
    }

    private fun generateGroupKey(quasiIdentifiers: Map<String, Any>): String {
        // Crear clave basada en rangos generalizados
        return quasiIdentifiers.entries.sortedBy { it.key }.joinToString("|") { (key, value) ->
            when (value) {
                is Number -> {
                    val range = getRangeForValue(value.toDouble())
                    "$key:${range.first}-${range.second}"
                }
                is String -> {
                    val generalized = generalizeString(value)
                    "$key:$generalized"
                }
                else -> "$key:${value.toString().take(3)}*"
            }
        }
    }

    private fun generalizeQuasiIdentifiers(group: List<PersonalData>): Map<String, Any> {
        if (group.isEmpty()) return emptyMap()

        val result = mutableMapOf<String, Any>()
        val allKeys = group.flatMap { it.quasiIdentifiers.keys }.distinct()

        allKeys.forEach { key ->
            val values = group.mapNotNull { it.quasiIdentifiers[key] }
            if (values.isNotEmpty()) {
                result[key] = generalizeValues(values)
            }
        }

        return result
    }

    private fun generalizeValues(values: List<Any>): Any {
        return when (val firstValue = values.first()) {
            is Number -> {
                val numbers = values.mapNotNull { (it as? Number)?.toDouble() }
                val min = numbers.minOrNull() ?: 0.0
                val max = numbers.maxOrNull() ?: 0.0
                "${min.toInt()}-${max.toInt()}"
            }
            is String -> {
                // Generalizar strings por prefijo común o categoría
                val commonPrefix = findCommonPrefix(values.map { it.toString() })
                if (commonPrefix.length >= 2) {
                    "$commonPrefix*"
                } else {
                    "***"
                }
            }
            else -> "***"
        }
    }

    private fun satisfiesLDiversity(group: List<PersonalData>, l: Int): Boolean {
        // Verificar que cada atributo sensible tenga al menos l valores distintos
        val sensitiveKeys = group.flatMap { it.sensitiveAttributes.keys }.distinct()

        return sensitiveKeys.all { key ->
            val distinctValues = group.mapNotNull { it.sensitiveAttributes[key] }.distinct()
            distinctValues.size >= l
        }
    }

    private fun diversifySensitiveAttributes(group: List<PersonalData>, l: Int): List<Map<String, Any>> {
        // Asegurar l-diversity suprimiendo o generalizando valores si es necesario
        return group.map { data ->
            data.sensitiveAttributes.mapValues { (key, value) ->
                val valuesInGroup = group.mapNotNull { it.sensitiveAttributes[key] }.distinct()
                if (valuesInGroup.size >= l) {
                    value // Mantener valor original si hay suficiente diversidad
                } else {
                    generalizeValue(value, inferDataType(key, value)) // Generalizar si no
                }
            }
        }
    }

    /**
     * Funciones para Differential Privacy
     */
    private fun calculateSensitivity(range: Pair<Double, Double>): Double {
        // Para consultas numéricas simples, la sensibilidad es típicamente 1
        // o la diferencia máxima posible en el resultado
        return minOf(1.0, range.second - range.first)
    }

    private fun generateLaplaceNoise(scale: Double): Double {
        // Generar ruido siguiendo distribución Laplace
        val u = random.nextDouble() - 0.5
        return -scale * sign(u) * ln(1 - 2 * abs(u))
    }

    /**
     * Funciones auxiliares
     */
    private fun getRangeForValue(value: Double): Pair<Double, Double> {
        // Crear rangos apropiados basados en el valor
        return when {
            value < 10 -> Pair(0.0, 10.0)
            value < 100 -> {
                val lower = (value / 10).toInt() * 10.0
                Pair(lower, lower + 10.0)
            }
            value < 1000 -> {
                val lower = (value / 100).toInt() * 100.0
                Pair(lower, lower + 100.0)
            }
            else -> {
                val lower = (value / 1000).toInt() * 1000.0
                Pair(lower, lower + 1000.0)
            }
        }
    }

    private fun generalizeString(value: String): String {
        return when {
            value.length <= 2 -> "*".repeat(value.length)
            value.length <= 5 -> value.take(1) + "*".repeat(value.length - 1)
            else -> value.take(2) + "*".repeat(value.length - 2)
        }
    }

    private fun findCommonPrefix(strings: List<String>): String {
        if (strings.isEmpty()) return ""

        val first = strings.first()
        var commonLength = 0

        for (i in first.indices) {
            if (strings.all { it.length > i && it[i] == first[i] }) {
                commonLength = i + 1
            } else {
                break
            }
        }

        return first.take(commonLength)
    }

    private fun inferDataType(key: String, value: Any): DataType {
        val keyLower = key.lowercase()

        return when {
            keyLower.contains("email") -> DataType.EMAIL
            keyLower.contains("phone") || keyLower.contains("telefono") -> DataType.PHONE
            keyLower.contains("address") || keyLower.contains("direccion") -> DataType.ADDRESS
            keyLower.contains("name") || keyLower.contains("nombre") -> DataType.PERSONAL_IDENTIFIER
            keyLower.contains("date") || keyLower.contains("fecha") -> DataType.DATE
            keyLower.contains("medical") || keyLower.contains("health") -> DataType.MEDICAL
            keyLower.contains("financial") || keyLower.contains("income") -> DataType.FINANCIAL
            keyLower.contains("location") || keyLower.contains("ubicacion") -> DataType.LOCATION
            value is Number -> DataType.NUMERIC
            else -> DataType.CUSTOM
        }
    }

    private fun getDefaultMaskingPolicy(dataType: DataType): MaskingPolicy {
        return MaskingPolicy(
            dataType = dataType,
            maskingMethod = MaskingMethod.HASH,
            strength = MaskingStrength.MEDIUM
        )
    }

    private fun generateAnonymousId(): String {
        val bytes = ByteArray(16)
        random.nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP)
    }

    private fun generateSalt(): String {
        val bytes = ByteArray(8)
        random.nextBytes(bytes)
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP)
    }

    private fun hashData(data: PersonalData): String {
        val dataString = "${data.id}${data.quasiIdentifiers}${data.sensitiveAttributes}${data.identifiers}"
        return try {
            val digest = java.security.MessageDigest.getInstance(HASH_ALGORITHM)
            val hash = digest.digest(dataString.toByteArray())
            android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            "HASH_ERROR"
        }
    }

    /**
     * Análisis de riesgo de re-identificación
     */
    fun assessReidentificationRisk(anonymizedData: List<AnonymizedData>): RiskAssessment {
        val totalRecords = anonymizedData.size
        var highRiskRecords = 0
        var mediumRiskRecords = 0
        var lowRiskRecords = 0

        // Agrupar por quasi-identifiers para evaluar unicidad
        val groups = anonymizedData.groupBy { it.generalizedQuasiIdentifiers.toString() }

        groups.forEach { (_, group) ->
            val groupSize = group.size
            when {
                groupSize == 1 -> highRiskRecords += groupSize
                groupSize <= 3 -> mediumRiskRecords += groupSize
                else -> lowRiskRecords += groupSize
            }
        }

        val highRiskPercentage = (highRiskRecords.toDouble() / totalRecords) * 100
        val mediumRiskPercentage = (mediumRiskRecords.toDouble() / totalRecords) * 100
        val lowRiskPercentage = (lowRiskRecords.toDouble() / totalRecords) * 100

        val overallRisk = when {
            highRiskPercentage > 20 -> AntiTamperingManager.RiskLevel.HIGH
            highRiskPercentage > 10 || mediumRiskPercentage > 50 -> AntiTamperingManager.RiskLevel.MEDIUM
            else -> AntiTamperingManager.RiskLevel.LOW
        }

        return RiskAssessment(
            overallRisk = overallRisk,
            totalRecords = totalRecords,
            highRiskRecords = highRiskRecords,
            mediumRiskRecords = mediumRiskRecords,
            lowRiskRecords = lowRiskRecords,
            highRiskPercentage = highRiskPercentage,
            mediumRiskPercentage = mediumRiskPercentage,
            lowRiskPercentage = lowRiskPercentage,
            recommendations = generateRiskRecommendations(overallRisk, highRiskPercentage)
        )
    }

    data class RiskAssessment(
        val overallRisk: AntiTamperingManager.RiskLevel,
        val totalRecords: Int,
        val highRiskRecords: Int,
        val mediumRiskRecords: Int,
        val lowRiskRecords: Int,
        val highRiskPercentage: Double,
        val mediumRiskPercentage: Double,
        val lowRiskPercentage: Double,
        val recommendations: List<String>
    )

    private fun generateRiskRecommendations(riskLevel: AntiTamperingManager.RiskLevel, highRiskPercentage: Double): List<String> {
        val recommendations = mutableListOf<String>()

        when (riskLevel) {
            AntiTamperingManager.RiskLevel.HIGH -> {
                recommendations.add("Incrementar el valor de k en k-anonymity")
                recommendations.add("Aplicar l-diversity para mayor protección")
                recommendations.add("Considerar differential privacy para datos numéricos")
                recommendations.add("Revisar políticas de generalización")
            }
            AntiTamperingManager.RiskLevel.MEDIUM -> {
                recommendations.add("Monitorear registros de alto riesgo")
                recommendations.add("Considerar mayor generalización para quasi-identifiers")
                if (highRiskPercentage > 15) {
                    recommendations.add("Aplicar supresión adicional")
                }
            }
            AntiTamperingManager.RiskLevel.LOW -> {
                recommendations.add("Mantener el nivel actual de anonimización")
                recommendations.add("Monitoreo regular de métricas de privacidad")
            }

            AntiTamperingManager.RiskLevel.CRITICAL -> TODO()
        }

        return recommendations
    }

    /**
     * Métricas de utilidad de datos
     */
    fun calculateDataUtility(
        originalData: List<PersonalData>,
        anonymizedData: List<AnonymizedData>
    ): DataUtilityMetrics {
        val informationLoss = calculateInformationLoss(originalData, anonymizedData)
        val dataQuality = calculateDataQuality(anonymizedData)
        val usabilityScore = calculateUsabilityScore(anonymizedData)

        return DataUtilityMetrics(
            informationLoss = informationLoss,
            dataQuality = dataQuality,
            usabilityScore = usabilityScore,
            overallUtility = (dataQuality + usabilityScore) / 2.0
        )
    }

    data class DataUtilityMetrics(
        val informationLoss: Double, // 0.0 = sin pérdida, 1.0 = pérdida total
        val dataQuality: Double, // 0.0 = baja calidad, 1.0 = alta calidad
        val usabilityScore: Double, // 0.0 = no utilizable, 1.0 = totalmente utilizable
        val overallUtility: Double // Métrica combinada
    )

    private fun calculateInformationLoss(
        original: List<PersonalData>,
        anonymized: List<AnonymizedData>
    ): Double {
        if (original.isEmpty() || anonymized.isEmpty()) return 1.0

        // Calcular pérdida basada en generalización y supresión
        var totalLoss = 0.0
        var totalFields = 0

        original.zip(anonymized).forEach { (orig, anon) ->
            orig.quasiIdentifiers.forEach { (key, origValue) ->
                val anonValue = anon.generalizedQuasiIdentifiers[key]
                totalLoss += calculateFieldLoss(origValue, anonValue)
                totalFields++
            }
        }

        return if (totalFields > 0) totalLoss / totalFields else 1.0
    }

    private fun calculateFieldLoss(original: Any, anonymized: Any?): Double {
        return when {
            anonymized == null -> 1.0 // Supresión completa
            anonymized.toString().contains("*") -> 0.5 // Masking parcial
            anonymized.toString().contains("-") -> 0.3 // Generalización a rango
            anonymized == original -> 0.0 // Sin pérdida
            else -> 0.7 // Transformación significativa
        }
    }

    private fun calculateDataQuality(anonymized: List<AnonymizedData>): Double {
        if (anonymized.isEmpty()) return 0.0

        var qualityScore = 0.0
        var totalFields = 0

        anonymized.forEach { record ->
            record.generalizedQuasiIdentifiers.forEach { (_, value) ->
                qualityScore += when {
                    value.toString().isEmpty() -> 0.0
                    value.toString() == "***" -> 0.2
                    value.toString().contains("*") -> 0.6
                    else -> 1.0
                }
                totalFields++
            }
        }

        return if (totalFields > 0) qualityScore / totalFields else 0.0
    }

    private fun calculateUsabilityScore(anonymized: List<AnonymizedData>): Double {
        if (anonymized.isEmpty()) return 0.0

        // Evaluar basado en diversidad y completitud
        val diversity = calculateDiversity(anonymized)
        val completeness = calculateCompleteness(anonymized)

        return (diversity + completeness) / 2.0
    }

    private fun calculateDiversity(anonymized: List<AnonymizedData>): Double {
        val allValues = anonymized.flatMap { it.generalizedQuasiIdentifiers.values }
        val uniqueValues = allValues.distinct().size
        val totalValues = allValues.size

        return if (totalValues > 0) uniqueValues.toDouble() / totalValues else 0.0
    }

    private fun calculateCompleteness(anonymized: List<AnonymizedData>): Double {
        var nonEmptyFields = 0
        var totalFields = 0

        anonymized.forEach { record ->
            record.generalizedQuasiIdentifiers.forEach { (_, value) ->
                if (value.toString().isNotEmpty() && value.toString() != "***") {
                    nonEmptyFields++
                }
                totalFields++
            }
        }

        return if (totalFields > 0) nonEmptyFields.toDouble() / totalFields else 0.0
    }
}