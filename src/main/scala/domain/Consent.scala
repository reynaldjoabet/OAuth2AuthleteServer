package domain

import java.time.LocalDateTime

final case class Consent(
    consentId: String,
    permissions: Array[String],
    status: String,
    creationDateTime: LocalDateTime,
    expirationDateTime: LocalDateTime,
    statusUpdateDateTime: LocalDateTime,
    clientId: Long,
    refreshToken: String
)
