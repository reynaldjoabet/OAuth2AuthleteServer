import java.nio.charset.StandardCharsets
import java.security.interfaces.{RSAPrivateCrtKey, RSAPublicKey}
import java.security.interfaces.RSAPrivateKey
import java.security.spec.{PKCS8EncodedKeySpec, RSAPublicKeySpec}
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.PublicKey
import java.time.Instant
import java.util.regex.Matcher
import java.util.regex.Pattern
import java.util.Base64
import java.util.UUID

import scala.jdk.CollectionConverters.*
import scala.util.Try

import cats.effect.kernel.Async
import cats.effect.syntax.all.*
import cats.syntax.all.*
import cats.Show

import com.auth0.jwk.Jwk
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.JWT
import com.neovisionaries.security.AESCipher
import com.nimbusds.jose
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader}
import com.nimbusds.jose.crypto.{ECDSASigner, Ed25519Signer}
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk._
import com.nimbusds.jose.jwk.{Curve, ECKey}
import com.nimbusds.jose.jwk.gen._
import com.nimbusds.jose.jwk.source.{JWKSource, RemoteJWKSet}
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.proc.BadJOSEException
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import domain.*
import exceptions.*
import org.bouncycastle.asn1.{ASN1EncodableVector, DERSet, DERUTCTime}
import org.bouncycastle.asn1.x509.Attribute
import org.bouncycastle.jcajce.provider.digest.{SHA1, SHA256, SHA3, SHA512}
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.http4s.headers.Authorization
import org.http4s.AuthScheme
import org.http4s.Credentials
import org.http4s.Header
import org.http4s.Headers
import org.http4s.Request
import org.typelevel.ci.*

// import com.nimbusds.jose.JOSEException
// import com.nimbusds.oauth2.sdk._
// import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
// import com.nimbusds.oauth2.sdk.http.HTTPResponse
// import com.nimbusds.oauth2.sdk.id.{ Issuer, State }
// import com.nimbusds.oauth2.sdk.token.BearerAccessToken
// import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet
// import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata
// import com.nimbusds.openid.connect.sdk.validators.IDTokenValidator
// import com.nimbusds.openid.connect.sdk.{ AuthenticationErrorResponse, _ }
// import com.nimbusds.openid.connect.sdk.claims._

package object utils {

  /**
    * Convert Authlete DTOs to strings. Implementations in this class MUST NOT output the secrets.
    * Currently, `subject` will not be output since it can be a actual name.
    */

  def showHelper[A](
      getters: A => (String, String)*
  ): Show[A] =
    self => self.getClass.getName + getters.map(g => g(self)).toMap.show

//proof generation methods

  def generateDPoPProof = 2

  // The confirmation
  val cnf = ConfirmationMethod.X509ThumbprintSha256

  /// Generates a DPoP (Demonstrating Proof-of-Possession) proof JWT header
/// for OAuth 2.0 requests.
///
/// Creates a signed JWT that proves possession of a private key and binds
/// the request to a specific endpoint, method, and time.
///
/// The proof can be used for both token requests and protected resource access.
///
/// Parameters:
/// - [clientId]: The OAuth client identifier
/// - [endpoint]: The complete URL of the endpoint being accessed
/// - [method]: The HTTP method of the request (e.g., 'POST', 'GET')
/// - [dPoPNonce]: The DPoP nonce provided by the server
/// - [authorizationServer]: Optional. The authorization server URL for access
///   token binding
/// - [accessToken]: Optional. The access token to bind to this proof
/// - [publicKey]: The encoded EC P-256 public key
/// - [privateKey]: The encoded EC P-256 private key for signing the proof
///
/// Returns a DPoP proof as a signed JWT string
/// in the format: header.payload.signature
///
/// The generated proof includes:
/// Header (JWK):
/// ```json
/// {
///   "alg": "ES256",
///   "typ": "dpop+jwt",
///   "jwk":{
///     "kty": "EC",
///     "crv": "P-256",
///     "x": "...",
///     "y": "..."
///   }
/// }
/// ```
///
/// Payload:
/// ```json
/// {
///   "sub": "client_id",
///   "htu": "endpoint_url",
///   "htm": "http_method",
///   "exp": timestamp + 60,
///   "jti": "random_unique_id",
///   "iat": timestamp,
///   "nonce": "dpop_nonce",
///   "iss": "client_id_or_auth_server",
///   "ath": "optional_access_token_hash"
/// }
/// ```

/// The proof is signed using ES256 (ECDSA with P-256 and SHA-256).

/// Note: The proof has a short expiration time (60 seconds)
/// to prevent replay attacks. A new proof should be generated for each request.

//keypair

  def createDpopToken(
      sub: String,
      htu: String,
      htm: String,
      exp: Long,
      jti: String,
      iat: Long,
      nonce: Option[String],
      iss: Option[String],
      ath: Option[String]
  ) = {}

  def generateDpopProof(
      htu: String,
      htm: String,
      exp: Long,
      jti: String,
      iat: Long,
      nonce: Option[String],
      iss: Option[String],
      ath: Option[String]
  ) = 0

  def withDpopHeader[F[_]](keypair: KeyPair, request: Request[F]): Request[F] = {

    // Convert the public key to a JWK
    val jwk = ""

    val dpop = JWT
      .create()
      .withClaim("htm", request.method.name)
      .withClaim("htu", request.uri.renderString)
      .withIssuedAt(Instant.now())           // iat
      .withJWTId(UUID.randomUUID().toString) // jti
      .withClaim("ath", "access token hash")
      .withClaim("nonce", "nonce")
      .withHeader(Map("typ" -> "dpop+jwt", "jwk" -> "json representation of public key").asJava)
      .sign(Algorithm.RSA256(null, keypair.getPrivate().asInstanceOf[RSAPrivateKey]))

    Header.Raw(CIString("X-Vault-Token"), "token")
    request.putHeaders(Header.Raw(ci"DPoP", dpop))
  }

  val headerParams = Set("typ", "alg", "jwk")
  val bodyParams   = Set("jti", "htm", "htu", "iat")

  def parseRSAPrivateKey(raw: String): Try[RSAPrivateCrtKey] = Try {
    val keyStripped = raw
      .replace("-----END PRIVATE KEY-----", "")
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("\n", "")
    val keyStrippedDecoded = Base64.getDecoder.decode(keyStripped)

    val keySpec = new PKCS8EncodedKeySpec(keyStrippedDecoded)
    val kf      = KeyFactory.getInstance("RSA")
    kf.generatePrivate(keySpec).asInstanceOf[RSAPrivateCrtKey]
  }

  def generateRSAKeyFromPrivate(privateKey: RSAPrivateCrtKey): RSAKey = {
    val publicKeySpec: RSAPublicKeySpec =
      new RSAPublicKeySpec(privateKey.getModulus, privateKey.getPublicExponent)
    val kf        = KeyFactory.getInstance("RSA")
    val publicKey = kf.generatePublic(publicKeySpec).asInstanceOf[RSAPublicKey]
    new RSAKey.Builder(publicKey).privateKey(privateKey).build()
  }

  def generateSessionId[F[_]: Async](SessionUser: String): F[String] =
    Async[F].delay {
      val mac    = MessageDigest.getInstance("SHA3-512")
      val digest = mac.digest(SessionUser.getBytes())
      // a 160-bit (20 byte) random value that is then URL-safe base64-encoded
      // byte[] buffer = new byte[20];
      Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
      // Base64.getEncoder().encodeToString(digest)
    }

  def extractSessionIdFromCookie[F[_]](
      name: String
  )(req: Request[F]): Either[OAuthException, String] =
    req
      .cookies
      .find(_.name === name)
      .map(_.content)
      .toRight(OAuthException.MissingAccessTokenException(""))

  Map("kty" -> "kty", "alg" -> "alg", "kid" -> "kid", "n" -> "n", "e" -> "e")

}
