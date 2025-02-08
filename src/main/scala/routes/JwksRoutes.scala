package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.*
import services.AuthleteService

final case class JwksRoutes[F[_]: Async](authleteService: AuthleteService[F]) extends Http4sDsl[F] {

  /**
    * JWK Set endpoint.
    *
    * <p> An OpenID Provider (OP) is required to expose its JSON Web Key Set document (JWK Set) so
    * that client applications can (1) verify signatures by the OP and (2) encrypt their requests to
    * the OP. The URI of a JWK Set endpoint can be found as the value of <b>{@code jwks_uri}</b> in
    * <a href= "http://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata" >OpenID
    * Provider Metadata</a> if the OP supports <a href=
    * "http://openid.net/specs/openid-connect-discovery-1_0.html">OpenID Connect Discovery 1.0</a>.
    * </p>
    *
    * @see
    *   <a href="http://tools.ietf.org/html/rfc7517" >RFC 7517, JSON Web Key (JWK)</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-core-1_0.htm" >OpenID Connect Core 1.0</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-discovery-1_0.html" >OpenID Connect
    *   Discovery 1.0</a>
    */
  val routes = HttpRoutes.of[F] { case GET -> Root / "jwks" =>
    authleteService
      .getServiceJwks()
      .flatMap(Ok(_, `Content-Type`(MediaType.application.`jwk-set+json`)))

  }

}
