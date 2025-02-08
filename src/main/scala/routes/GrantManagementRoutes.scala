package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.GMRequest
import com.authlete.common.dto.GMResponse
import com.authlete.common.types.GMAction
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.`WWW-Authenticate`
import org.http4s.headers.Authorization
import org.typelevel.ci.*
import services.AuthleteService
import services.DpopService.*

/**
  * An implementation of Grant Management Endpoint.
  *
  * @see
  *   <a href="https://openid.net/specs/fapi-grant-management.html" >Grant Management for OAuth
  *   2.0</a>
  */

final case class GrantManagementRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  val routes = HttpRoutes.of[F] {

    /**
      * The entry point for grant management 'query' requests.
      */
    case req @ GET -> Root / "gm" / grantId =>
      val gmRequest = GMRequest()
        // .setGmAction(if req.method.name == "DELETE" then GMAction.REVOKE else GMAction.QUERY)
        .setGmAction(GMAction.QUERY)
        .setGrantId(grantId)
        .setAccessToken(extractAccessToken(req).orNull)
        // .setClientCertificate(extractClientCertificate(req))
        .setDpop(extractDpop(req).orNull)

      processGMResponse(gmRequest)

    /**
      * The entry point for grant management 'revoke' requests.
      */
    case req @ DELETE -> Root / "gm" / grantId =>
      val gmRequest = GMRequest()
        // .setGmAction(if req.method.name == "DELETE" then GMAction.REVOKE else GMAction.QUERY)
        .setGmAction(GMAction.REVOKE)
        .setGrantId(grantId)
        .setAccessToken(extractAccessToken(req).orNull)
        // .setClientCertificate(extractClientCertificate(req))
        .setDpop(extractDpop(req).orNull)

      processGMResponse(gmRequest)

  }

  private def processGMResponse(body: GMRequest): F[Response[F]] =
    authleteService
      .gm(body)
      .flatMap { resp =>
        val content                  = resp.getResponseContent()
        val dpopNonceHeader          = Option(resp.getDpopNonce()).map(Header.Raw(ci"DPoP-Nonce", _))
        val responseHeaders: Headers = dpopNonceHeader.map(Headers(_)).getOrElse(Headers.empty)
      resp.getAction() match {
        case GMResponse.Action.OK => Status.Ok(content, responseHeaders)
        case GMResponse.Action.NO_CONTENT =>
          Status
            .NoContent()
            .map { resp =>
              // dpopNonceHeader.map(resp.addHeader(_)).getOrElse(resp)
              resp
            }
        case GMResponse.Action.UNAUTHORIZED =>
          Status.Unauthorized(
            `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8"))),
            headers = responseHeaders
          )
        case GMResponse.Action.FORBIDDEN => Status.Forbidden(content, responseHeaders)
        case GMResponse.Action.NOT_FOUND => Status.NotFound(content, responseHeaders)
        case GMResponse.Action.CALLER_ERROR | GMResponse.Action.AUTHLETE_ERROR =>
          Status.InternalServerError(content, responseHeaders)
        // case GMResponse.Action.AUTHLETE_ERROR => Status.InternalServerError(content,responseHeaders)
      }
      }

  private def extractAccessToken(req: Request[F]) =
    req
      .headers
      .get[Authorization]
      .flatMap(
        _.credentials match {
          case Credentials.Token(AuthScheme.Bearer, token) => Option(token)
          case _                                           => None
        }
      )

  private def extractDpop(req: Request[F]) =
    req.headers.get(ci"Authorization").map(_.head.value).flatMap(extractDpopToken(_))

}
