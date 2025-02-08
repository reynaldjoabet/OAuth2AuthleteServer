package services

import java.nio.charset.StandardCharsets
import java.security.spec.ECParameterSpec
import java.security.MessageDigest
import java.security.PublicKey
import java.util.regex.Pattern
import java.util.Base64
import java.util.UUID

import scala.jdk.CollectionConverters.*
import scala.util.Try

import cats.syntax.all.*

import com.auth0.jwk.Jwk
import com.auth0.jwt.algorithms.Algorithm
import com.nimbusds.jose
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jwt.JWT
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import exceptions.OAuthException
import org.bouncycastle.jcajce.provider.digest.SHA3
import org.bouncycastle.jcajce.provider.digest.SHA512
import org.http4s.Request
import org.typelevel.ci.*

/**
  * Performs validation of DPoP proofs according to RFC-9449.
  */

/**
  * An implementation of OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer
  * (DPoP).
  *
  * @see
  *   <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-dpop">DPoP draft
  *   specification</a>
  */
object DpopService {

  /**
    * Validates and returns a DPoP proof from an HTTP request.
    *
    * This method can be invoked in two modes: * If no JWK is passed in using the `expected`
    * parameter, a proof is extracted from the request, validated accordingly and returned. It is
    * assumed, that the proof is not bound to an access token. `null` may be returned if no proof is
    * present. * If a JWK is passed in, the proof is expected to be bound to an access token. An
    * `IllegalArgumentException` will be thrown if no proof is present. The proof is validated
    * accordingly. It is checked that the used key matches the passed in JWK and the ath claim is
    * checked based on the authorization header.
    */

  def validate = 0

  def verifyDpopProofJwkThumbprint = 0

// uses Dpop Scheme and not Bearer scheme
  // a signed jwt is a JWS
  // an encrypted jwt is called JWE
  // jwt is the base class with two sub classes, jwe and jse

  /**
    * Get the DPoP proof JWT (the value of the {@code DPoP} HTTP header).
    *
    * <p> See <i>"OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer
    * (DPoP)"</i> for details. </p>
    *
    * @return
    *   The DPoP proof JWT.
    */

  def extractDpopProof[F[_]](
      req: Request[F]
  ): Either[OAuthException, String] =
    req.headers.get(ci"DPoP") match {
      case None =>
        Either.left[OAuthException, String](
          OAuthException.DpopValidationError("Missing DPoP proof header")
        )
      case Some(dpopProofHeaders) =>
        if (dpopProofHeaders.length > 1)
          Either.left[OAuthException, String](
            OAuthException.DpopValidationError("Multiple DPoP proof headers are not allowed.")
          )
        else Either.right[OAuthException, String](dpopProofHeaders.head.value)
    }

    // DPOP Scheme

  def getDpopTokenFromAuthzHeader[F[_]](
      req: Request[F]
  ): Either[OAuthException, String] =
    req.headers.get(ci"Authorization") match {
      case None =>
        Either
          .left[OAuthException, String](OAuthException.DpopValidationError("Missing DPoP header"))
      case Some(dpopHeaders) =>
        if (dpopHeaders.length > 1)
          Either.left[OAuthException, String](
            OAuthException.DpopValidationError("Multiple DPoP proof headers are not allowed.")
          )
        else {
          val header      = dpopHeaders.head
          val tokenPrefix = "DPoP "
          val value       = header.value
          if value.startsWith(tokenPrefix) then
            Either.right[OAuthException, String](value.stripPrefix(tokenPrefix).trim)
          else
            Either.left[OAuthException, String](
              OAuthException.DpopValidationError("DPoP token has an invalid syntax")
            )

        }

    }

  def extractJwkFromJwtHeader(values: Map[String, Object]): Jwk = Jwk.fromValues(values.asJava)

  // "RS256"
  // "ES256"
  // https://github.com/danielfett/draft-dpop/blob/d1acf0db08fbcf269dcda598034eb9a7067ea815/main.md?plain=1#L344

  // SHA-256 thumbprint of the public key.

  def calculateJwkThumbprint(publicKey: PublicKey): String = {
    val mac    = MessageDigest.getInstance("SHA-256")
    val digest = mac.digest(publicKey.getEncoded())
    Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
  }

  def calculateHash(accessToken: String): String = {
    val mac = MessageDigest.getInstance("SHA-256")
    Base64.getUrlEncoder().withoutPadding().encodeToString(mac.digest(accessToken.getBytes()))
  }

  def validateNonce = 0

  // (jti) claim is absent in DPoP token

  protected val rsaKeyGenerator: RSAKeyGenerator = new RSAKeyGenerator(2048)

  val getCurrentJwks: RSAKey = {
    rsaKeyGenerator
      .keyUse(KeyUse.SIGNATURE)
      .algorithm(new jose.Algorithm("RS256"))
      .keyID(UUID.randomUUID().toString)
      .generate()
  }

  def algoFromJwk(alg: String, jwk: JWK): Option[Algorithm] =
    jwk match {
      case rsaKey: RSAKey =>
        alg match {
          case "RS256" => Some(Algorithm.RSA256(rsaKey.toRSAPublicKey, null))
          case "RS384" => Some(Algorithm.RSA384(rsaKey.toRSAPublicKey, null))
          case "RS512" => Some(Algorithm.RSA512(rsaKey.toRSAPublicKey, null))
        }
      case ecKey: ECKey =>
        alg match {
          case "EC256" => Some(Algorithm.ECDSA256(ecKey.toECPublicKey, null))
          case "EC384" => Some(Algorithm.ECDSA384(ecKey.toECPublicKey, null))
          case "EC512" => Some(Algorithm.ECDSA512(ecKey.toECPublicKey, null))
        }
      case _ => None
    }

  def publicKeyFromJwk(alg: String, jwk: JWK): Option[PublicKey] =
    jwk match {
      case rsaKey: RSAKey =>
        alg match {
          case "RS256" | "RS384" | "RS512" => Some(rsaKey.toRSAPublicKey)
        }
      case ecKey: ECKey =>
        alg match {
          case "EC256" | "EC384" | "EC512" => Some(ecKey.toECPublicKey)
        }
      case _ => None
    }

  private def encodeSHA3512(input: String): String = {
    val digest: MessageDigest = new SHA3.Digest512
    val output: Array[Byte]   = digest.digest(input.getBytes)
    val encoded: Array[Byte]  = Base64.getUrlEncoder.withoutPadding.encode(output)
    new String(encoded)
  }

  private def digestSHA2512(input: Array[Byte]): String = {
    val digest: MessageDigest = new SHA512.Digest
    val output: Array[Byte]   = Base64.getUrlEncoder.withoutPadding.encode(digest.digest(input))
    new String(output)
  }

  // : Either[Throwable, JWTClaimsSet]
  def parse(token: String, keySet: JWKSet) =
    Try(JWSObject.parse(token).getHeader.getAlgorithm).getOrElse {
      JWSAlgorithm.RS256
    }

  def verifyAndDecodeJwtToken(jwtToken: String, secretKey: String): Try[JWTClaimsSet] =
    Try {
      val signedJWT = SignedJWT.parse(jwtToken)
      val verifier  = new MACVerifier(secretKey.getBytes)
      if (!signedJWT.verify(verifier)) throw new Exception("JWT verification failed")
      signedJWT.getJWTClaimsSet
    }

  def extractDpopToken(token: String): Option[String] = {

    /**
      * A regular expression for extracting "DPoP {access_token}" in the `Authorization` request
      * header.
      */
    val dpopPattern = Pattern.compile("^DPoP *([^ ]+) *$", Pattern.CASE_INSENSITIVE)
    val matcher     = dpopPattern.matcher(token)
    if (matcher.matches()) Some(matcher.group(1)) else None
  }

  def extractBearerToken(token: String): Option[String] = {
    if (token == null) None
    else {
      val bearerPattern = Pattern.compile("^Bearer *([^ ]+) *$", Pattern.CASE_INSENSITIVE)
      val matcher       = bearerPattern.matcher(token)
      if (matcher.matches()) Some(matcher.group(1)) else None
    }
  }

  def extractClientAttestation[F[_]](req: Request[F]) =
    req.headers.get(ci"OAuth-Client-Attestation").map(_.head.value)

  def extractClientAttestationPop[F[_]](req: Request[F]) =
    req.headers.get(ci"OAuth-Client-Attestation-PoP").map(_.head.value)

  def validateDpopHeader(dpop: String) = ???

  def validateDpopPayload(dpop: String) = ???

  def validateDpopHeader(dpop: JWT) = {
    // val jwk = JSONWebKey.fromJSONObject(dpop.getHeader().getJwk())
  }

  def validateDpopPayload(dpop: JWT) = ???

  /**
    * Validate dpop proof header.
    *
    * @param httpMethod
    *   HTTP method of the request.
    * @param httpURL
    *   HTTP URL of the request,
    * @param dPoPProof
    *   DPoP header of the request.
    * @param token
    *   Access token / Refresh token.
    * @return
    * @throws ParseException
    *   Error while retrieving the signedJwt.
    * @throws IdentityOAuth2Exception
    *   Error while validating the dpop proof.
    */

  def isValidDPoPProof(httpMethod: String, httpURL: String, dPoPProof: String, token: String) = {
    // ParseException

    // IdentityOAuth2Exception

    val signedJwt = SignedJWT.parse(dPoPProof)
    val header    = signedJwt.getHeader()

    validateDPoPPayload(
      httpMethod,
      httpURL,
      signedJwt.getJWTClaimsSet(),
      token
    ) && validateDPoPHeader(header)
  }

  def validateDPoPPayload(
      httpMethod: String,
      httpURL: String,
      dPoPProof: JWTClaimsSet,
      token: String
  ): Boolean = ???

  // checkJwtClaimSet(jwtClaimsSet) && checkDPoPHeaderValidity(jwtClaimsSet) && checkJti(jwtClaimsSet) &&
  // checkHTTPMethod(httpMethod, jwtClaimsSet) && checkHTTPURI(httpURL, jwtClaimsSet) && checkAth(token, jwtClaimsSet);

  def validateDPoPHeader(header: JWSHeader): Boolean = ???
  // checkJwk(header) && checkAlg(header) && checkHeaderType(header)

  /// checkJwtClaimSet(jwtClaimsSet) && checkDPoPHeaderValidity(jwtClaimsSet) && checkJti(jwtClaimsSet) &&
  // checkHTTPMethod(httpMethod, jwtClaimsSet) && checkHTTPURI(httpURL, jwtClaimsSet);

  def checkAth(token: String, jwtClaimsSet: JWTClaimsSet): Boolean = {

    val ath = Option(jwtClaimsSet.getClaim("ath"))
    ath.fold(new Exception("DPoP Proof access token hash is empty.")) { hash =>

      val digest = MessageDigest.getInstance("SHA-256")

      val hashBytes = digest.digest(token.getBytes(StandardCharsets.US_ASCII))

      // Encode the hash using base64url encoding
      val hashFromToken = Base64.getUrlEncoder().withoutPadding().encodeToString(hashBytes)
    if (!(hash.toString() == hashFromToken)) {
      // log.error("DPoP Proof access token hash mismatch.");
      // throw new IdentityOAuth2ClientException(DPoPConstants.INVALID_DPOP_PROOF, DPoPConstants.INVALID_DPOP_PROOF);
    }
    }

    true
  }

  def validateDpopHeader              = 0
  def getDPoPJwkThumbprint()          = 0
  def getThumbprintOfKeyFromDpopProof = 0

  def validateDpopThumprint(existingThumprint: String, requestThumprint: String) = 0

  def validateDpopThumprintIsPresent(dpopJkt: String, state: String) = 0

  def defaultKeyPair(spec: ECParameterSpec) =
    // val keyUtil = new EcKeyUtil()

    ???

}
