package services

import java.time.Clock
import java.time.Instant

import scala.jdk.CollectionConverters._

import cats.effect.kernel.Sync
import cats.syntax.all.*

import com.auth0.jwk.Jwk
import com.auth0.jwt
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.impl.PayloadClaimsHolder
import com.auth0.jwt.interfaces
import com.auth0.jwt.interfaces.ECDSAKeyProvider
import com.auth0.jwt.interfaces.RSAKeyProvider
import com.auth0.jwt.JWT
import com.auth0.jwt.JWTVerifier
import com.auth0.jwt.JWTVerifier.BaseVerification
import com.auth0.jwt.RegisteredClaims
import config.OAuth2ClientConfig
import domain.User

sealed abstract class JwtService[F[_]] {

  def getAccessTokenVerifier(algo: Algorithm): F[JWTVerifier]
  def getDpopTokenVerifier(algo: Algorithm): F[JWTVerifier]
  def getIdTokenVerifier(algo: Algorithm): F[JWTVerifier]

  def createAccessToken(algo: Algorithm): F[String]
  // def verifyAccessToken(token: String): F[User]

}
