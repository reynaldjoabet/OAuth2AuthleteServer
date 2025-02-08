package routes

import scala.jdk.CollectionConverters.*

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.IntrospectionRequest
import com.authlete.common.dto.IntrospectionResponse
import com.authlete.common.dto.StandardIntrospectionRequest
import com.authlete.common.web.URLCoder
import domain.ResourceServer
import domain.SessionUser
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.`WWW-Authenticate`
import org.http4s.headers.Authorization
import org.http4s.Credentials.AuthParams
import org.http4s.Credentials.Token
import requests.IntrospectionRequestParam
import services.AuthleteService

final case class IntrospectionRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  /**
    * Introspection endpoint which supports RFC 7662.
    *
    * @see
    *   <a href="http://tools.ietf.org/html/rfc7662" >RFC 7662, OAuth 2.0 Token Introspection</a>
    */

  val routes = AuthedRoutes.of[SessionUser, F] {

    // "2.1. Introspection Request" in RFC 7662 says as follows:
    //
    //   To prevent token scanning attacks, the endpoint MUST also require
    //   some form of authorization to access this endpoint, such as client
    //   authentication as described in OAuth 2.0 [RFC6749] or a separate
    //   OAuth 2.0 access token such as the bearer token described in OAuth
    //   2.0 Bearer Token Usage [RFC6750].  The methods of managing and
    //   validating these authentication credentials are out of scope of this
    //   specification.
    //
    // Therefore, this API must be protected in some way or other.
    // Basic Authentication and Bearer Token are typical means, and
    // both use the value of the 'Authorization' header.
    //
    case req @ POST -> Root / "introspection" as session =>
      // Authenticate the API caller.
      // boolean authenticated = authenticateApiCaller(authorization);

      // // If the API caller does not have necessary privileges to call this API.
      // if (authenticated == false)
      // {
      //     // Return "401 Unauthorized".
      //     return Response.status(Status.UNAUTHORIZED).build();
      // }

      // Status.Unauthorized("")

      req
        .req
        .as[UrlForm]
        .flatMap { form =>
          val parameters = form.values.map((k, v) => (k, v.toVector.toArray)).asJava

          // "2.1. Introspection Request" in RFC 7662 says as follows:
          //
          //   To prevent token scanning attacks, the endpoint MUST also require
          //   some form of authorization to access this endpoint, such as client
          //   authentication as described in OAuth 2.0 [RFC6749] or a separate
          //   OAuth 2.0 access token such as the bearer token described in OAuth
          //   2.0 Bearer Token Usage [RFC6750].  The methods of managing and
          //   validating these authentication credentials are out of scope of this
          //   specification.
          //
          // Therefore, this API must be protected in some way or other.
          // Basic Authentication and Bearer Token are typical means, and
          // both use the value of the 'Authorization' header.
        val basicCredentials = req
          .req
          .headers
          .get[Authorization]
          .flatMap {
            _.credentials match {
              case Token(AuthScheme.Basic, token) => BasicCredentials.fromString(token)
              case Token(_, _)                    => None
              case AuthParams(authScheme, params) =>
                None
            }
          }

        // get from db using credentials(resource server id) from above
        // Fetch the information about the resource server from DB.
        basicCredentials
          .fold(Async[F].raiseError(new Exception()))(cred =>
            Async[F].delay[Option[ResourceServer]](Some(null)).map((_, cred.password))
          )
          .flatMap { (resourceServer, secret) =>
            if authenticateResourceServer(resourceServer, secret)
            then {

              // credentials.fold(
              //           Status.Unauthorized(
              //             `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8")))
              //           )
              //         )(processIntrospectionResponse(_, introspectionRequest))
              val accessToken = Option("") // from header
              val server      = resourceServer.get
              val params      = URLCoder.formUrlEncode(parameters)
              val standardIntrospectionRequest = StandardIntrospectionRequest()
                .setParameters(params)
                .setWithHiddenProperties(false) // withHiddenProperties)
                .setHttpAcceptHeader("httpAcceptHeader")
                .setRsUri(server.uri)
                .setIntrospectionSignAlg(server.introspectionSignAlg)
                .setIntrospectionEncryptionAlg(server.introspectionEncryptionAlg)
                .setIntrospectionEncryptionEnc(server.introspectionEncryptionEnc)
                .setSharedKeyForSign(server.sharedKeyForIntrospectionResponseSign)
                .setSharedKeyForEncryption(server.sharedKeyForIntrospectionResponseEncryption)
                .setPublicKeyForEncryption(server.publicKeyForIntrospectionResponseEncryption)

              val introspectionRequest: IntrospectionRequest = IntrospectionRequest()
                .setDpop("dpop")
                .setDpopNonceRequired(true)
                .setSubject("mysubject")
                .setAcrValues(Array())
                .setClientCertificate(???)
                .setHtm("")
                .setHtu("")
                .setToken(accessToken.orNull)
                .setMaxAge(89)
                .setScopes(Array())
                .setResources(Array())
              // .setRequestBodyContained()
              // .setTargetUri("")
              // .setUri("")

              processIntrospectionResponse(introspectionRequest)

            } else
              Status.Unauthorized(
                `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8")))
              )

          }
          .recoverWith(_ =>
            Status.Unauthorized(
              `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8")))
            )
          )
        }
  }

  private def processIntrospectionResponse(
      body: IntrospectionRequest
  ): F[Response[F]] =
    authleteService
      .introspection(body)
      .flatMap { resp =>
        resp.getAction() match {
          case IntrospectionResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError()
          case IntrospectionResponse.Action.BAD_REQUEST  => Status.BadRequest()
          case IntrospectionResponse.Action.UNAUTHORIZED => ???
          case IntrospectionResponse.Action.FORBIDDEN    => Status.Forbidden()
          case IntrospectionResponse.Action.OK           => ???
        }
      }

//rsEntity.getSecret().equals(credentials.getPassword())
  private def authenticateResourceServer(resourceServer: Option[ResourceServer], secret: String) =
    resourceServer.fold(false)(_.secret == secret)

}
