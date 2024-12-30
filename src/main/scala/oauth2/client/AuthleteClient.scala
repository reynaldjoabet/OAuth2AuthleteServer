package oauth2
package client

import com.authlete.common.dto.{
  ApiResponse,
  AuthorizationFailRequest,
  AuthorizationFailResponse,
  AuthorizationIssueRequest,
  AuthorizationIssueResponse,
  AuthorizationRequest,
  AuthorizationResponse,
  Client,
  IntrospectionRequest,
  IntrospectionResponse,
  RevocationRequest,
  RevocationResponse,
  TokenRequest,
  TokenResponse
}
import cats.effect.Concurrent
import sttp.client4.{Backend}
import org.http4s.client.{Client => HttpClient}
import org.http4s.*
import org.http4s.Method.*
import config.AuthleteConfig
import org.http4s.headers.*
import org.typelevel.log4cats.Logger
import cats.Show
import cats.syntax.show.*
import io.circe.generic.auto.*
import io.circe.syntax.*
import io.circe.parser
import io.circe.Encoder
import io.circe.Decoder
import org.http4s.circe.CirceEntityCodec.circeEntityEncoder
import cats.syntax.all.*
import AuthleteClientUtils.*

import cats.effect.syntax.all.*
import cats.effect.kernel.Sync
import cats.effect.kernel.Async
import org.http4s.Uri.Path
import org.checkerframework.checker.units.qual.m
import com.authlete.common.dto.Client

trait AuthleteClient[F[_]] {

  /** /api/client/get endpoint
    *
    * [[https://docs.authlete.com/#client-get-api]]
    */
  def clientGet(clientId: String): F[Either[ApiResponse, Client]]

  def clientGet2(clientId: String): F[Client | ApiResponse]

  /** /api/auth/authorization endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-api]]
    */
  def authorization(
      request: AuthorizationRequest
  ): F[Either[ApiResponse, AuthorizationResponse]]

  /** /api/auth/authorization/issue endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-issue-api]]
    */
  def authorizationIssue(
      request: AuthorizationIssueRequest
  ): F[Either[ApiResponse, AuthorizationIssueResponse]]

  /** /api/auth/authorization/fail endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-fail-api]]
    */
  def authorizationFail(
      request: AuthorizationFailRequest
  ): F[Either[ApiResponse, AuthorizationFailResponse]]

  /** /api/auth/token endpoint
    *
    * [[https://docs.authlete.com/#token-endpoint]]
    */
  def token(request: TokenRequest): F[Either[ApiResponse, TokenResponse]]

  /** /api/auth/introspection endpoint
    *
    * [[https://docs.authlete.com/#introspection-endpoint]]
    */
  def introspection(
      request: IntrospectionRequest
  ): F[Either[ApiResponse, IntrospectionResponse]]

  /** /api/auth/revocation endpoint
    *
    * [[https://docs.authlete.com/#revocation-endpoint]]
    */
  def revocation(
      request: RevocationRequest
  ): F[Either[ApiResponse, RevocationResponse]]
}

final class AuthleteClientImpl[F[_]: Async](
    client: HttpClient[F],
    config: AuthleteConfig,
    logger: Logger[F]
) extends AuthleteClient[F] {

  private val baseUri =
    Uri.unsafeFromString(s"https://${config.host}:${config.port}")

  private def basicRequest(method: Method, uri: Uri) = Request[F](
    method = method,
    uri = uri,
    headers = Headers(
      Authorization(BasicCredentials(config.apiKey, config.apiSecret)),
      `Content-Type`(MediaType.application.json)
    )
  )

  override def clientGet(clientId: String): F[Either[ApiResponse, Client]] = {
    val api = "/client/get"
    val uri =
      baseUri.withPath(Path.unsafeFromString(s"/api/client/get/$clientId"))
    val request = basicRequest(Method.GET, uri)

    logRequest(api, "ClientId" -> clientId) *>
      client.expect[Either[ApiResponse, Client]](request).attempt.flatMap {
        case Right(response) =>
          response.fold(
            e => handleError(api, e).map(Left(_)),
            body => logResponse(api, body).as(body).map(Right(_))
          )
        case Left(e) => handleError(api, e.getMessage).as(Left(ApiResponse()))
      }
  }

  override def clientGet2(clientId: String): F[Client | ApiResponse] = {
    val api = "/client/get"
    val uri =
      baseUri.withPath(Path.unsafeFromString(s"/api/client/get/$clientId"))
    val request = basicRequest(Method.GET, uri)

    logRequest(api, "ClientId" -> clientId) *>
      client.expect[Client | ApiResponse](request).attempt.flatMap {
        case Right(resp) =>
          resp match {
            case a: ApiResponse =>
              logResponse(api, a).as(a)
            case c: Client =>
              logResponse(api, c).as(c)
          }
        case Left(e) => handleError(api, e.getMessage).as(ApiResponse())
      }
  }

  override def authorization(
      request: AuthorizationRequest
  ): F[Either[ApiResponse, AuthorizationResponse]] = {
    val api = "/auth/authorization"
    logRequest(api, request)
    val uri = baseUri.withPath(Path.unsafeFromString("/api/auth/authorization"))
    val req = basicRequest(Method.POST, uri).withEntity(request)

    client
      .expect[Either[ApiResponse, AuthorizationResponse]](req)
      .attempt
      .flatMap {
        case Right(value) =>
          // val body =
          // logResponse(api, body)
          // Sync[F].pure(Right(body))
          ???
        case Left(e) => ??? // handleError(api, e.getMessage)
      }
  }

  override def authorizationIssue(
      request: AuthorizationIssueRequest
  ): F[Either[ApiResponse, AuthorizationIssueResponse]] = {
    val api = "/auth/authorization/issue"
    logRequest(api, request)
    val uri =
      baseUri.withPath(Path.unsafeFromString("/api/auth/authorization/issue"))
    val req = basicRequest(Method.POST, uri).withEntity(request)

    client
      .expect[Either[ApiResponse, AuthorizationIssueResponse]](req)
      .attempt
      .flatMap {
        case Right(value) =>
          // val body = json.parseJson(value, classOf[AuthorizationIssueResponse])
          // logResponse(api, body)
          // Sync[F].pure(Right(body))
          ???
        case Left(e) => ??? /// handleError(api, e.getMessage)
      }
  }

  override def authorizationFail(
      request: AuthorizationFailRequest
  ): F[Either[ApiResponse, AuthorizationFailResponse]] = {
    val api = "/auth/authorization/fail"
    logRequest(api, request)
    val uri =
      baseUri.withPath(Path.unsafeFromString("/api/auth/authorization/fail"))
    val req = basicRequest(Method.POST, uri).withEntity(request)

    client
      .expect[Either[ApiResponse, AuthorizationFailResponse]](req)
      .attempt
      .flatMap {
        case Right(value) =>
          // val body = json.parseJson(value, classOf[AuthorizationFailResponse])
          // logResponse(api, body)
          // Sync[F].pure(Right(body))

          ???
        case Left(e) => ??? // handleError(api, e.getMessage)
      }
  }

  override def token(
      request: TokenRequest
  ): F[Either[ApiResponse, TokenResponse]] = {
    val api = "/auth/token"
    logRequest(api, request)
    val uri = baseUri.withPath(Path.unsafeFromString("/api/auth/token"))
    val req = basicRequest(Method.POST, uri).withEntity(request)

    client.expect[Either[ApiResponse, TokenResponse]](req).attempt.flatMap {
      case Right(value) =>
        // val body = json.parseJson(value, classOf[TokenResponse])
        // logResponse(api, body)
        // Sync[F].pure(Right(body))
        ???
      case Left(e) => ??? // handleError(api, e.getMessage)
    }
  }

  override def introspection(
      request: IntrospectionRequest
  ): F[Either[ApiResponse, IntrospectionResponse]] = {
    val api = "/auth/introspection"
    logRequest(api, request)
    val uri = baseUri.withPath(Path.unsafeFromString("/api/auth/introspection"))
    val req = basicRequest(Method.POST, uri).withEntity(request)

    client
      .expect[Either[ApiResponse, IntrospectionResponse]](req)
      .attempt
      .flatMap {
        case Right(value) =>
          // val body = json.parseJson(value, classOf[IntrospectionResponse])
          // logResponse(api, body)
          // Sync[F].pure(Right(body))

          ???
        case Left(e) => ??? /// handleError(api, e.getMessage)
      }
  }

  override def revocation(
      request: RevocationRequest
  ): F[Either[ApiResponse, RevocationResponse]] = {
    post(request, classOf[RevocationResponse], "auth", "revocation")
  }

  private def post[A: Show: Encoder, B: Show: Decoder](
      request: A,
      cls: Class[B],
      path: String*
  ): F[Either[ApiResponse, B]] = {
    //   val apiName = path.mkString("/", "/", "")
    //   val uri = baseUri.withPath(s"/api/${path.mkString("/")}")
    //   val req = basicRequest(Method.POST, uri).withEntity(request)
    //   logRequest(apiName, request) *>
    //     client.expect[Either[ApiResponse, B]](req).attempt.flatMap {
    //       case Right(value) =>
    //         val body = json.parseJson(value, cls)
    //         logResponse(apiName, body)
    //         Sync[F].pure(Right(body))
    //       case Left(e) => handleError(apiName, e.getMessage)
    //     }
    // }
    ???
  }

  // private def handleResponse[A: Show](
  //     api: String,
  //     body: A
  // ): F[Either[ApiResponse, A]] = {

  //   logResponse(api, body)
  //   //Sync[F].pure(Right(body))
  //   ???
  // }

  private def handleError(api: String, body: ApiResponse): F[ApiResponse] = {
    logResponse(api, body).as(body)
  }
  private def handleError(api: String, body: String): F[Unit] = {
    logResponse(api, body)
  }

  private def logRequest[A: Show](api: String, body: A): F[Unit] =
    logger.info(s"Authlete Request ${api}; ${body}")

  private def logRequest(api: String, body: String): F[Unit] =
    logger.info(s"Authlete Request ${api}; ${body}")
  private def logResponse[A: Show](api: String, body: A): F[Unit] =
    logger.info(s"Authlete Response ${api}; ${body}")

  private def logResponse(api: String, body: String): F[Unit] =
    logger.info(s"Authlete Response ${api}; ${body}")

}

object AuthleteClient {
  // def apply[F[_]](client: HttpClient[F]): AuthleteClient[F] = new AuthleteClientImpl(client)
}
