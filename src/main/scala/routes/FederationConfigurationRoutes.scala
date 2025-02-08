package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.FederationConfigurationRequest
import com.authlete.common.dto.FederationConfigurationResponse
import com.authlete.common.types.EntityType
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.`Content-Type`
import services.AuthleteService

/**
  * An implementation of the entity configuration endpoint.
  *
  * <p> An OpenID Provider that supports <a href=
  * "https://openid.net/specs/openid-federation-1_0.html">OpenID Federation 1.0</a> must provide an
  * endpoint that returns its <b>entity configuration</b> in the JWT format. The URI of the endpoint
  * is defined as follows: </p>
  *
  * <ol> <li>Entity ID + {@code /.well-known/openid-federation} <li>Host component of Entity ID +
  * {@code /.well-known/openid-federation} + Path component of Entity ID (The same rule in <a href=
  * "https://www.rfc-editor.org/rfc/rfc8414.html">RFC 8414</a>) </ol>
  *
  * <p> <b>Entity ID</b> is a URL that identifies an OpenID Provider (and other entities including
  * Relying Parties, Trust Anchors and Intermediate Authorities) in the context of OpenID Federation
  * 1.0. </p>
  *
  * <p> Note that OpenID Federation 1.0 is supported since Authlete 2.3. </p>
  *
  * @see
  *   <a href="https://openid.net/specs/openid-federation-1_0.html" >OpenID Federation 1.0</a>
  */

final case class FederationConfigurationRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {
//"/.well-known/openid-federation")

  val routes = HttpRoutes.of[F] { case GET -> Root / ".well-known/openid-federation" =>
    /**
      * The request to Authlete's /federation/configuration API.
      */
    val federationConfigurationRequest =
      new FederationConfigurationRequest().setEntityTypes(
        Array(
          EntityType.OPENID_PROVIDER,
          EntityType.OPENID_CREDENTIAL_ISSUER
        )
      )

    authleteService
      .federationConfiguration(federationConfigurationRequest)
      .flatMap { resp =>
        val content = resp.getResponseContent()
        resp.getAction() match {
          case FederationConfigurationResponse.Action.OK =>
            // 200 OK; application/entity-statement+jwt
            Status.Ok(content, `Content-Type`(MediaType.application.jwt))
          case FederationConfigurationResponse.Action.NOT_FOUND =>
            // 404 Not Found
            Status.NotFound(content)
          case FederationConfigurationResponse.Action.INTERNAL_SERVER_ERROR =>
            // 500 Internal Server Error
            Status.InternalServerError(content)
        }
      }

  }

}
