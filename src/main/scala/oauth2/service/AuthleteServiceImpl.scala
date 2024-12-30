package oauth2
package service

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
import org.slf4j.LoggerFactory
import sttp.client4.{asString, basicRequest, Response, Backend}
import sttp.model.{MediaType, Uri}
import config.AuthleteConfig
import cats.Show
import oauth2.client.AuthleteClientUtils.*

trait Json {
  def renderJson(body: Any): String
  def parseJson[T](json: String, cls: Class[T]): T
}

final private class AuthleteServiceImpl[F[_]](
    backend: Backend[F],
    json: Json,
    config: AuthleteConfig
) extends AuthleteService[F] {

  private val logger = LoggerFactory.getLogger(this.getClass)

  private val baseRequest = basicRequest.auth
    .basic(config.apiKey, config.apiSecret)
    .contentType(MediaType.ApplicationJson)
    .response(asString)
    .readTimeout(config.requestTimeout)
  private val baseUri = Uri("https", config.host, config.port)

  override def clientGet(
      clientId: String
  ): F[Response[Either[ApiResponse, Client]]] = {
    val api = "/client/get"
    // logRequest(api, "ClientId" -> clientId)
    baseRequest
      .get(baseUri.withPath("api", "client", "get", clientId))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[Client])
          // logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def authorization(
      request: AuthorizationRequest
  ): F[Response[Either[ApiResponse, AuthorizationResponse]]] = {
    val api = "/auth/authorization"
    // logRequest(api, request)
    baseRequest
      .post(baseUri.withPath("api", "auth", "authorization"))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[AuthorizationResponse])
          logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def authorizationIssue(
      request: AuthorizationIssueRequest
  ): F[Response[Either[ApiResponse, AuthorizationIssueResponse]]] = {
    val api = "/auth/authorization/issue"
    // logRequest(api, request)
    baseRequest
      .post(baseUri.withPath("api", "auth", "authorization", "issue"))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[AuthorizationIssueResponse])
          logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def authorizationFail(
      request: AuthorizationFailRequest
  ): F[Response[Either[ApiResponse, AuthorizationFailResponse]]] = {
    val api = "/auth/authorization/fail"
    // logRequest(api, request)
    baseRequest
      .post(baseUri.withPath("api", "auth", "authorization", "fail"))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[AuthorizationFailResponse])
          logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def token(
      request: TokenRequest
  ): F[Response[Either[ApiResponse, TokenResponse]]] = {
    val api = "/auth/token"
    // logRequest(api, request)
    baseRequest
      .post(baseUri.withPath("api", "auth", "token"))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[TokenResponse])
          logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def introspection(
      request: IntrospectionRequest
  ): F[Response[Either[ApiResponse, IntrospectionResponse]]] = {
    val api = "/auth/introspection"
    // logRequest(api, request)
    baseRequest
      .post(baseUri.withPath("api", "auth", "introspection"))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) =>
          val body = json.parseJson(value, classOf[IntrospectionResponse])
          logResponse(api, body)
          Right(body)
        case Left(value) => handleError(api, value)
      }
      .send(backend)
  }

  override def revocation(
      request: RevocationRequest
  ): F[Response[Either[ApiResponse, RevocationResponse]]] = {
    post(request, classOf[RevocationResponse], "auth", "revocation")
  }

  private def post[A: Show, B: Show](
      request: A,
      cls: Class[B],
      path: String*
  ): F[Response[Either[ApiResponse, B]]] = {
    val apiName = path.mkString("/", "/", "")
    // logRequest(apiName, request)
    baseRequest
      // Authlete endpoint begins with path `/api`
      .post(baseUri.withPath("api", path: _*))
      .body(json.renderJson(request))
      .mapResponse {
        case Right(value) => handleResponse[B](apiName, value, cls)
        case Left(value)  => handleError(apiName, value)
      }
      .send(backend)
  }

  private def handleResponse[A: Show](
      api: String,
      bodyStr: String,
      cls: Class[A]
  ): Right[Nothing, A] = {
    val body = json.parseJson(bodyStr, cls)
    // logResponse(api, body)
    Right(body)
  }

  private def handleError(
      api: String,
      bodyStr: String
  ): Left[ApiResponse, Nothing] = {
    val body = json.parseJson(bodyStr, classOf[ApiResponse])
    // logResponse(api, body)
    Left(body)
  }

  private def logRequest[A: Show](api: String, body: A): Unit = {
    // logger.info(s"Authlete Request {}; {}", api, body.show)
  }

  private def logResponse[A: Show](api: String, body: A): Unit = {
    // logger.info(s"Authlete Response {}; {}", api, body.show)
  }
}
