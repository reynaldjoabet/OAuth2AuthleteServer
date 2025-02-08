package domain

import java.util.Date

import com.authlete.common.dto.Client
import io.circe.Codec

//Emphasizes the user associated with a session.
final case class SessionUser(
    user: User,
    acrs: Array[String],
    client: Client,
    authTime: Date,
    ticket: String,
    claimNames: Array[String],
    claimLocales: Array[String],
    idTokenClaims: String,
    requestedClaimsForTx: Array[String],
    // StringArray[] requestedVerifiedClaimsForTx:Array[String]
    oldIdaFormatUsed: Boolean
) //derives Codec

//UserSession
//Emphasizes that it is a session belonging to a user or a representation of the user's session.
