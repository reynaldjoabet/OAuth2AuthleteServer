package middleware

import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.cert.Certificate
import java.security.cert.CertificateException
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.Key
import java.security.KeyStore
import java.security.UnrecoverableKeyException
import java.util.concurrent.TimeUnit
import java.util.Base64

// import cats._
// import cats.data._
import cats.data.Kleisli
import cats.effect.kernel.*
import cats.effect.kernel.Async
import cats.effect.syntax.all.*
import cats.syntax.all.*

import com.auth0.jwk.Jwk
import com.auth0.jwk.JwkException
import com.auth0.jwk.JwkProvider
import com.auth0.jwk.JwkProviderBuilder
import com.auth0.jwk.SigningKeyNotFoundException
import com.auth0.jwk.UrlJwkProvider
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTCreationException
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.Claim
import com.auth0.jwt.interfaces.DecodedJWT
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.Header
import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import config.OAuth2ClientConfig
import domain.*
import exceptions.OAuthException
import logging.syntax.*
import org.http4s.*
import org.typelevel.ci.*
import org.typelevel.log4cats.Logger
import services.AuthleteService
import services.DpopService.*
import services.JwtService

object DpopValidationMiddleware {

  /**
    * Validate if the DPoP Proof JWT is indeed signed by the given key. This can be used to verify
    * if the DPoP proof is not signed by the key bound to the client
    */

  private[middleware] def validateDpopProofToken[F[_]: Sync: Logger](
      dpopProofToken: String,
      config: OAuth2ClientConfig,
      jwtService: JwtService[F],
      req: Request[F]
  ) = for {

    dpopProofJwt <- Sync[F].delay(JWT.decode(dpopProofToken)) // Sync[F].catchNonFatal(JWT.decode(dpopToken))

    _ <- Sync[F]
           .raiseError[Unit](
             new OAuthException.DpopValidationError(s"the alg cannot be equal to none")
           )
           .whenA(dpopProofJwt.getAlgorithm() == "none")

    _ <- Sync[F]
           .raiseError[Unit](
             OAuthException.DpopValidationError(s"DPoP header 'typ' is not 'dpop+jwt'")
           )
           .whenA(dpopProofJwt.getType() != "dpop+jwt")

    dpopJwk <- getJwkFromDpopToken(dpopProofJwt)

    _ <- Sync[F]
           .raiseError[Unit](
             OAuthException.DpopValidationError(s"cannot use a private key for DPoP")
           )
           .whenA(dpopJwk.isPrivate())

    algorithm = algoFromJwk(dpopProofJwt.getAlgorithm(), dpopJwk.toPublicJWK()) // extractPublicKeyFromJwk(dpopJwk)
    _ <-
      Sync[F]
        .raiseError[Unit](
          OAuthException.DpopValidationError(s"DPoP signature algorithm (alg) in JWT header is not a supported algorithm (ES256, ES384, Ed25519)")
        )
        .whenA(!algorithm.isDefined)

    //  _ <- Sync[F]
    //                .raiseError[Unit](
    //                  OAuthException.DpopValidationError(s"the public key is missing")
    //                )
    //                .whenA(pu)

    verifiedDpopProofJwt <-
      jwtService
        .getDpopTokenVerifier(algorithm.get)
        .map(_.verify(dpopProofToken))
        .adaptErr(_ =>
          OAuthException.DpopValidationError(
            "DPoP signature does not correspond to the public key (jwk) in the JWT header"
          )
        ) // "the DPoP signature is not valid"))

    _ <- Sync[F]
           .raiseError[Unit](
             new OAuthException.DpopValidationError(s"auth is null")
           )
           .whenA(dpopProofJwt.getClaim("ath").isNull()) // .isNull checks if the value is null,isMissing checks the claim
    // The signature of the JWS is verified, now for checking the content
    htu = dpopProofJwt.getHeaderClaim("htu").asString()

    _ <- Sync[F]
           .raiseError[Unit](
             new OAuthException.DpopValidationError(s"htu in DPoP does not match the HTTP URI") // The request uri does not correspond to the (htu) claim in DPoP token
           )
           .whenA(htu != req.uri.toString())

    htm = dpopProofJwt.getHeaderClaim("htm").asString()

    _ <- Sync[F]
           .raiseError[Unit](
             new OAuthException.DpopValidationError(s"htm in DPoP does not match the HTTP method") // The request method does not correspond to the (htm) claim in DPoP token
           )
           .whenA(htm != req.method.name)

    publicKey = publicKeyFromJwk(dpopProofJwt.getAlgorithm(), dpopJwk.toPublicJWK())
    // nonce = dpopProofJwt.getHeaderClaim("nonce").asString()
    // _     = req.headers.get(ci"Dpop-Nonce").map(_.head.value) // [backend_nonce] does not correspond to the (nonce) claim in DPoP token (base64url encoded)
  } yield (verifiedDpopProofJwt, publicKey.get)

  private def validateAccessToken[F[_]: Sync: Logger](
      token: String,
      config: OAuth2ClientConfig,
      jwtService: JwtService[F]
  ): F[DecodedJWT] = for {
    jwt <- Sync[F]
             .delay(JWT.decode(token))
             .logError(e =>
               "No issuer claim provided in the JWT, unable to determine origin LTI platform"
             )
    jwk       <- getJwkFromAccessToken(jwt.getKeyId(), config.issuer)
    algorithm <- Algorithm.RSA256(jwk.getPublicKey().asInstanceOf[RSAPublicKey], null).pure
    // InvalidPublicKeyException("Invalid algorithm to generate key", e)
    verifiedJwt <-
      jwtService.getAccessTokenVerifier(algorithm).map(_.verify(token))
  } yield verifiedJwt

  private def userFromJwt(jwt: DecodedJWT): User = ???

  def validate[F[_]: Sync: Logger](
      token: String,
      config: OAuth2ClientConfig,
      jwtService: JwtService[F]
  ): Kleisli[F, Request[F], Either[
    JWTVerificationException | JwkException | OAuthException,
    User
  ]] = Kleisli { req =>
    (getDpopTokenFromAuthzHeader(req), extractDpopProof[F](req)) match {
      case (Right(accessToken), Right(dpopToken)) =>
        validateDpopProofToken(token, config, jwtService, req).flatMap {
          (verifiedDpopProofJwt, publicKey) =>
            // Base64.getUrlDecoder().decode(verifiedDpopJwt.getClaim("ath").asString())

            validateAccessToken(token, config, jwtService)
              .flatMap { verifiedAccessToken =>
                val thumbprintFromDpopToken = calculateJwkThumbprint(publicKey)
                // jktFromAccessToken
                val thumbprint = verifiedAccessToken
                  .getClaim("cnf")
                  .asMap()
                  .get("jkt")
                  .asInstanceOf[String]

              val hashFromDpop = verifiedDpopProofJwt.getClaim("ath").asString()
              val tokenHash    = calculateHash(accessToken)

              // Verified that DPoP signature key match thumbprint in auth token
              Sync[F]
                .raiseError[Unit](
                  new OAuthException.DpopValidationError(
                    s"the jkt from the DPoP JWT didn't match the thumbprint from the access token; cnf.jkt"
                  )
                )
                .whenA(thumbprint != thumbprintFromDpopToken) *> Sync[F]
                .raiseError[Unit](
                  new OAuthException.DpopValidationError(
                    s"ath in DPoP does not match the token hash"
                  )
                )
                .whenA(tokenHash != hashFromDpop)
                .as(verifiedAccessToken)

              }
              .map { jwt =>
                val userRoles = Option(jwt.getClaim("roles").asArray(classOf[String]))
                  .map(_.toList)
                  .getOrElse(List.empty[String])

                Either.cond[OAuthException, User](
                  true,             // requiredScopes.forall(userRoles.toSet),
                  userFromJwt(jwt), // An access token represents that the client application has been authorized by the user
                  OAuthException.InsufficientScope("requiredScopes.mkString", "missing scopes")
                )
              }

        }
      case (Left(ex), Right(dpopToken)) =>
        // "Missing Authorization header"
        Either.left[OAuthException, User](ex).pure
      case (Right(accesToken), Left(ex)) =>
        // "Missing DPoP header"
        Either.left[OAuthException, User](ex).pure
      case (Left(_), Left(ex)) =>
        Either
          .left[OAuthException, User](
            OAuthException
              .DpopValidationError("both Authorization header and DPoP headers are missing")
          )
          .pure
    }

  }

  // val dpopJwt = decodeJwt(dpopHeader) // Implement JWT decoding logic

  private val getCachedProvider = (domain: String) =>
    new JwkProviderBuilder(domain)
      .cached(10, 12, TimeUnit.MINUTES)
      // .rateLimited(10, 1, TimeUnit.MINUTES)
      .build()
    // could fail

  private def getJwkFromAccessToken[F[_]: Sync: Logger](kid: String, domain: String): F[Jwk] =
    Sync[F]
      .blocking(getCachedProvider(domain).get(kid))
      .adaptErr(ex => new SigningKeyNotFoundException("", ex.getCause()))
      .logError(e => s"Unable to retrieve kid with exception $e")
  //            throw new NetworkException("Cannot obtain jwks from url " + url.toString(), e);

  private def getJwkFromDpopToken[F[_]: Sync: Logger](decodedJwt: DecodedJWT): F[JWK] = Sync[F]
    .delay(new String(Base64.getDecoder.decode(decodedJwt.getHeader)))
    .map(JWK.parse)

  // Jwk.fromValues()

  // the DPoP Nonce (nonce) claim is missing.

  // DPoP Nonce (nonce) value '{proof_jwt.nonce}' does not match expected

}
