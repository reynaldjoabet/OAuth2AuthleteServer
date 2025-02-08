import java.security.interfaces.RSAPublicKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.util.regex.Pattern
import java.util.Date

import com.nimbusds.jose
import com.nimbusds.jose.{JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.crypto.impl.AESCryptoProvider
import com.nimbusds.jose.crypto.impl.CipherHelper
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jca
import com.nimbusds.jose.jwk
import com.nimbusds.jose.jwk.{Curve, ECKey}
import com.nimbusds.jose.jwk.gen.JWKGenerator
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.mint
import com.nimbusds.jose.proc
import com.nimbusds.jose.produce
import com.nimbusds.jose.shaded
import com.nimbusds.jose.util
import com.nimbusds.jose.ActionRequiredForJWSCompletionException
import com.nimbusds.jose.Algorithm
import com.nimbusds.jose.CompletableJWSObjectSigning
import com.nimbusds.jose.CompressionAlgorithm
import com.nimbusds.jose.CriticalHeaderParamsAware
import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.Header
import com.nimbusds.jose.HeaderParameterNames
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObject
import com.nimbusds.jose.JOSEObjectJSON
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JOSEProvider
import com.nimbusds.jose.JSONSerializable
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.JWEObjectJSON
import com.nimbusds.jose.JWEProvider
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.JWSSignerOption
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.KeyException
import com.nimbusds.jose.KeyLengthException
import com.nimbusds.jose.KeySourceException
import com.nimbusds.jose.Payload
import com.nimbusds.jose.PayloadTransformer
import com.nimbusds.jose.PlainHeader
import com.nimbusds.jose.PlainObject
import com.nimbusds.jose.RemoteKeySourceException
import com.nimbusds.jose.Requirement
import com.nimbusds.jose.UnprotectedHeader
import com.nimbusds.jwt
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc
import com.nimbusds.jwt.proc.BadJWTException
import com.nimbusds.jwt.proc.ClockSkewAware
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import com.nimbusds.jwt.proc.JWTClaimsSetAwareJWSKeySelector
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier
import com.nimbusds.jwt.proc.JWTProcessor
import com.nimbusds.jwt.proc.JWTProcessorConfiguration
import com.nimbusds.jwt.util
import com.nimbusds.jwt.util.DateUtils
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.JWTParser
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import javax.crypto.spec.SecretKeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

DateUtils.fromSecondsSinceEpoch(12)

DateUtils.nowWithSecondsPrecision()

DateUtils.toSecondsSinceEpoch(Date())

Security.getProvider("BCFIPS")

def generateIV(randomGen: SecureRandom) = {
  val bytes = new Array[Byte](Byte.MaxValue)
  randomGen.nextBytes(bytes);
  bytes
}

generateIV(new SecureRandom())

val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

//cipher = CipherHelper.getInstance("AES/CBC/PKCS5Padding", provider)
//val secretKey:SecretKey=
//val keyspec = new SecretKeySpec(secretKey.getEncoded(), "AES");

val keyspec = new SecretKeySpec(Array[Byte](2), "AES")

//AESCryptoProvider

val claimsSet = new JWTClaimsSet.Builder()
  .subject("joe")
  .expirationTime(new Date(1300819380 * 1000L))
  .claim("http://example.com/is_root", true)
  .build()

// Create JWS payload
val payload = new Payload("Hello world!")

// Create JWS header with HS256 algorithm
val header = new JWSHeader.Builder(JWSAlgorithm.HS256).contentType("text/plain").build

// Create JWS object
val jwsObject = new JWSObject(header, payload)

// Create HMAC signer
val signer = new MACSigner("sharedKeytyrtrtrtrgrgfgfgfgfgfgfgfgfgfgfgfgf".getBytes)
jwsObject.sign(signer)

// Serialise JWS object to compact format
jwsObject.serialize

def decodeJws(s: String) = {

  // Parse back and check signature
  val jwsObject         = JWSObject.parse(s)
  val verifier          = new MACVerifier("sharedKey".getBytes())
  val verifiedSignature = jwsObject.verify(verifier)

  println(verifiedSignature match {
    case true  => "Verified JWS signature!"
    case false => "Bad JWS signature!"
  })

  jwsObject
}

val verifier = (publicKey: RSAPublicKey) => new RSASSAVerifier(publicKey)

/// Cryptographic operations using the Edwards-curve Digital Signature Algorithm (EdDSA)
/// with the Ed25519 elliptic curve

val token = """{

  "sub": "bob",

  "aud": "https://resource.example.com",

  "iss": "https://your.authorization.server.com",

  "exp": 1622302400,

  "iat": 1622301800,

  "jti": "abcd-123",

  "cnf": {

    "jkt": "H3FAnEgNeDnFbLWHh3cR3B63wI2U0hm0ZTuIV_8I8EU"

  }

}""".stripMargin

Payload(token).toJSONObject().values().toArray()(6).toString()

object Dpop {

  def parse(token: String): Option[String] = {
    val dpopPattern = Pattern.compile("^DPoP *([^ ]+) *$", Pattern.CASE_INSENSITIVE)
    val matcher     = dpopPattern.matcher(token)
    if (matcher.matches()) Some(matcher.group(1)) else None
  }

}

object Bearer {

  def parse(token: String): Option[String] = {
    if (token == null) None
    else {
      val bearerPattern = Pattern.compile("^Bearer *([^ ]+) *$", Pattern.CASE_INSENSITIVE)
      val matcher       = bearerPattern.matcher(token)
      if (matcher.matches()) Some(matcher.group(1)) else None
    }
  }

}

Bearer.parse(null)

Bearer.parse("Bearer hhhgffff")

Bearer.parse("Bearer ")
