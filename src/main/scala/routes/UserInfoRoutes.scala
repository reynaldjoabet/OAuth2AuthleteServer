package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.UserInfoIssueRequest
import com.authlete.common.dto.UserInfoIssueResponse
import com.authlete.common.dto.UserInfoRequest
import com.authlete.common.dto.UserInfoResponse
import domain.SessionUser
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.*
import services.AuthleteService

/**
  * An implementation of userinfo endpoint (<a href=
  * "https://openid.net/specs/openid-connect-core-1_0.html#UserInfo" >OpenID Connect Core 1&#x2E;0,
  * 5&#x2E;3&#x2E; UserInfo Endpoint</a>).
  *
  * @see
  *   <a href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfo" >OpenID Connect Core
  *   10, 5.3. UserInfo Endpoint</a>
  */

final case class UserInfoRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  val routes = AuthedRoutes.of[SessionUser, F] {
    case GET -> Root / "userinfo" as session =>
      val missingAccessTokenChallenge = "Bearer error=\"invalid_token\",error_description=\""
        + "An access token must be sent as a Bearer Token. "
        + "See OpenID Connect Core 1.0, 5.3.1. UserInfo Request for details.\""
      lazy val userInfoReques: UserInfoRequest = UserInfoRequest()

      lazy val userInfoIssueRequest: UserInfoIssueRequest = UserInfoIssueRequest()

      authleteService
        .userinfo(userInfoReques)
        .flatMap { resp =>
          resp.getAction() match {
            case UserInfoResponse.Action.INTERNAL_SERVER_ERROR => Status.InternalServerError()
            case UserInfoResponse.Action.BAD_REQUEST           => Status.BadRequest()
            case UserInfoResponse.Action.UNAUTHORIZED          => ??? // Status.Unauthorized()
            case UserInfoResponse.Action.FORBIDDEN             => Status.Forbidden()
            case UserInfoResponse.Action.OK =>
              processUserInfoIssueResponse(userInfoIssueRequest)
          }
        }
    case req @ POST -> Root / "userinfo" as session =>
      ???

  }

  private def processUserInfoIssueResponse(body: UserInfoIssueRequest): F[Response[F]] =
    authleteService
      .userinfoIssue(body)
      .flatMap { resp =>
        val content = resp.getResponseContent()
        resp.getAction() match {
          case UserInfoIssueResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError(content)
          case UserInfoIssueResponse.Action.BAD_REQUEST => Status.BadRequest(content)
          case UserInfoIssueResponse.Action.UNAUTHORIZED =>
            Status.Unauthorized(
              `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8")))
            ) // WWW-Authenticate: Bearer realm="DigitalOcean", error="invalid_token", error_description="The access token is invalid"
          case UserInfoIssueResponse.Action.FORBIDDEN => Status.Forbidden()
          case UserInfoIssueResponse.Action.JSON =>
            Ok(content, `Content-Type`(MediaType.application.json, Charset.`UTF-8`))
          case UserInfoIssueResponse.Action.JWT =>
            Ok(content, `Content-Type`(MediaType.application.jwt, Charset.`UTF-8`))
        }
      }

}
