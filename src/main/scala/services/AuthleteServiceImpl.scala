package services

import cats.effect.kernel.Resource
import cats.effect.syntax.all.*
import cats.effect.Concurrent
import cats.syntax.all.*

import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.JWT
import com.authlete.common.api.*
import com.authlete.common.dto
import com.authlete.common.dto.*
import com.authlete.common.types.TokenStatus
import config.AuthleteConfig
import org.checkerframework.checker.units.qual.g
import org.http4s.circe.CirceEntityCodec.*
import org.http4s.circe.CirceEntityDecoder._
import org.http4s.client.{Client => HttpClient}
import org.http4s.dsl.request
import org.http4s.headers.*
import org.http4s.AuthScheme
import org.http4s.BasicCredentials
import org.http4s.Credentials.Token
import org.http4s.Header
import org.http4s.Headers
import org.http4s.MediaType
import org.http4s.Method
import org.http4s.Request
import org.http4s.Uri
import org.http4s.Uri.Path
import org.typelevel.ci.*
import org.typelevel.log4cats.Logger

final class AuthleteServiceImpl[F[_]: Concurrent] private (
    client: HttpClient[F],
    config: AuthleteConfig,
    logger: Logger[F]
) extends AuthleteService[F] {

  private val baseUri: Uri =
    Uri.unsafeFromString(config.baseUrl)

  private def basicRequest(method: Method, uri: Uri): Request[F] = Request[F](
    method = method,
    uri = uri,
    headers = Headers(
      // Authorization(BasicCredentials(config.apiKey, config.apiSecret)),//V3 API requires an access token, not a key and secret
      Authorization(Token(AuthScheme.Bearer, config.auth)),
      `Content-Type`(MediaType.application.json)
    )
  )

  private def deleteRequest(uri: Uri): Request[F] = Request[F](
    method = Method.DELETE,
    uri = uri,
    headers = Headers(
      Authorization(Token(AuthScheme.Bearer, config.auth))
    )
  )

  private def postRequest(uri: Uri): Request[F] = basicRequest(Method.POST, uri)

  private def getRequest(uri: Uri): Request[F] =
    basicRequest(Method.GET, uri)

  override def authorization(
      body: AuthorizationRequest
  ): F[AuthorizationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/authorization")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[AuthorizationResponse](request)
      .flatTap(resp =>
        logger.info(s"Authorization response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def authorizationFail(
      body: AuthorizationFailRequest
  ): F[AuthorizationFailResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/authorization/fail")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[AuthorizationFailResponse](request)
      .flatTap(resp =>
        logger.info(s"AuthorizationFail response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def authorizationIssue(
      body: AuthorizationIssueRequest
  ): F[AuthorizationIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/auth/authorization/issue"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[AuthorizationIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"AuthorizationIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def token(body: TokenRequest): F[TokenResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenResponse](request)
      .flatTap(resp =>
        logger.info(s"Token response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def tokenCreate(body: TokenCreateRequest): F[TokenCreateResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/create")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenCreateResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenCreate response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def tokenDelete(token: String): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/auth/token/delete/$token"
      )
    )
    val request = basicRequest(Method.DELETE, uri)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(s"Token deleted successfully: $status")
        case status => logger.error(s"Failed to delete token: $status")
      }

  }

  override def tokenFail(body: TokenFailRequest): F[TokenFailResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/fail")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenFailResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenFail response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def tokenIssue(body: TokenIssueRequest): F[TokenIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/issue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def tokenRevoke(body: TokenRevokeRequest): F[TokenRevokeResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/revoke")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenRevokeResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenRevoke response  with result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def tokenUpdate(body: TokenUpdateRequest): F[TokenUpdateResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/update")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenUpdateResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenUpdate response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def getTokenList(): F[TokenListResponse] =
    getTokenList(None, None, 0, 0, false, TokenStatus.ALL)

  override def getTokenList(tokenStatus: TokenStatus): F[TokenListResponse] =
    getTokenList(None, None, 0, 0, false, tokenStatus)

  override def getTokenList(
      clientIdentifier: String,
      subject: String
  ): F[TokenListResponse] =
    getTokenList(
      Some(clientIdentifier),
      Some(subject),
      0,
      0,
      false,
      TokenStatus.ALL
    )

  override def getTokenList(
      clientIdentifier: String,
      subject: String,
      tokenStatus: TokenStatus
  ): F[TokenListResponse] =
    getTokenList(
      Some(clientIdentifier),
      Some(subject),
      0,
      0,
      false,
      tokenStatus
    )

  override def getTokenList(start: Int, end: Int): F[TokenListResponse] =
    getTokenList(None, None, start, end, true, TokenStatus.ALL)

  override def getTokenList(
      start: Int,
      end: Int,
      tokenStatus: TokenStatus
  ): F[TokenListResponse] =
    getTokenList(None, None, start, end, true, tokenStatus)

  override def getTokenList(
      clientIdentifier: String,
      subject: String,
      start: Int,
      end: Int
  ): F[TokenListResponse] =
    getTokenList(
      Some(clientIdentifier),
      Some(subject),
      start,
      end,
      true,
      TokenStatus.ALL
    )

  override def getTokenList(
      clientIdentifier: Option[String],
      subject: Option[String],
      start: Int,
      end: Int,
      rangeGiven: Boolean,
      tokenStatus: TokenStatus
  ): F[TokenListResponse] = {

    val queryParams = Map(
      "clientIdentifier" -> clientIdentifier,
      "subject"          -> subject,
      "tokenStatus"      -> tokenStatus.toString
    ).collect { case (k, Some(v)) => k -> v }
      .concat(
        if (rangeGiven)
          Map(
            "start" -> start.toString,
            "end"   -> end.toString
          )
        else Map.empty[String, String]
      )

    val uri = baseUri
      .withPath(
        Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/list")
      )
      .withQueryParams(queryParams)
    val request = basicRequest(Method.GET, uri).withHeaders(Accept(MediaType.application.json))
    // .withHeaders(Authorization(BasicCredentials(config.apiKey, config.apiSecret)))

    client
      .expect[TokenListResponse](request)
      .flatTap(resp => logger.info("successfully retrieved token list"))

  }

  override def revocation(body: RevocationRequest): F[RevocationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/revocation")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[RevocationResponse](request)
      .flatTap(resp =>
        logger.info(s"Revocation response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def userinfo(body: UserInfoRequest): F[UserInfoResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/userinfo")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[UserInfoResponse](request)
      .flatTap(resp =>
        logger.info(s"UserInfo response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def userinfoIssue(
      body: UserInfoIssueRequest
  ): F[UserInfoIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/userinfo/issue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[UserInfoIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"UserInfoIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def introspection(
      body: IntrospectionRequest
  ): F[IntrospectionResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/introspection")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[IntrospectionResponse](request)
      .flatTap(resp =>
        logger.info(s"Introspection response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def standardIntrospection(
      body: StandardIntrospectionRequest
  ): F[StandardIntrospectionResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/auth/introspection/standard"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[StandardIntrospectionResponse](request)
      .flatTap(resp =>
        logger.info(s"StandardIntrospection response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def createService(service: Service): F[Service] = {

    val uri     = baseUri.withPath(Path.unsafeFromString(s"/api/service/create"))
    val request = basicRequest(Method.POST, uri).withEntity(service)
    client.expect[Service](request)
    // .flatTap(resp => logger.info(s"Create "))"
  }

  override def createServie(service: Service): F[Service] =
    createService(service)

  override def deleteService(): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/delete")
    )
    val request = basicRequest(Method.DELETE, uri)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(s"Service deleted successfully: $status")
        case status => logger.error(s"Failed to delete service: $status")
      }

  }

  override def getService(): F[Service] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/get")
    )
    val request = basicRequest(Method.GET, uri)
    client.expect[Service](request)
  }

  override def getServiceList(): F[ServiceListResponse] =
    getServiceList(0, 0, false)

  override def getServiceList(start: Int, end: Int): F[ServiceListResponse] =
    getServiceList(start, end, true)

  override def getServiceList(
      start: Int,
      end: Int,
      rangeGiven: Boolean
  ): F[ServiceListResponse] = {
    val queryParams =
      if (rangeGiven)
        Map(
          "start" -> start.toString,
          "end"   -> end.toString
        )
      else Map.empty[String, String]

    val uri = baseUri
      .withPath(Path.unsafeFromString(s"/api/service/get/list"))
      .withQueryParams(queryParams)
    val request = basicRequest(Method.GET, uri).withHeaders(Accept(MediaType.application.json))

    client
      .expect[ServiceListResponse](request)
      .flatTap(resp => logger.info("successfully retrieved service list"))

  }

  override def updateService(service: Service): F[Service] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/update")
    )
    val request = basicRequest(Method.POST, uri).withEntity(service)
    client.expect[Service](request)

  }

  override def getServiceJwks(): F[String] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/jwks/get")
    )

    client
      .expect[String](basicRequest(Method.GET, uri))
      .flatTap(resp => logger.info("successfully retrieved service jwks"))

  }

  override def getServiceJwks(
      pretty: Boolean,
      includePrivateKeys: Boolean
  ): F[String] = {

    val queryParams = Map(
      "pretty"             -> pretty.toString,
      "includePrivateKeys" -> includePrivateKeys.toString
    )
    val uri = baseUri
      .withPath(
        Path.unsafeFromString(s"/api/${config.apiKey}/service/jwks/get")
      )
      .withQueryParams(queryParams)

    client
      .expect[String](basicRequest(Method.GET, uri))
      .flatTap(resp => logger.info("successfully retrieved service jwks"))
  }

  override def getServiceConfiguration(): F[String] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/configuration")
    )

    client
      .expect[String](basicRequest(Method.GET, uri))
      .flatTap(resp => logger.info("successfully retrieved service configuration"))
  }

  override def getServiceConfiguration(pretty: Boolean): F[String] = {

    val queryParams = Map(
      "pretty" -> pretty.toString
    )
    val uri = baseUri
      .withPath(
        Path.unsafeFromString(s"/api/${config.apiKey}/service/configuration")
      )
      .withQueryParams(queryParams)

    client
      .expect[String](basicRequest(Method.GET, uri))
      .flatTap(resp => logger.info("successfully retrieved service configuration"))
  }

  override def getServiceConfiguration(
      body: ServiceConfigurationRequest
  ): F[String] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/service/configuration")
    )

    client
      .expect[String](postRequest(uri).withEntity(body))
      .flatTap(resp => logger.info("successfully retrieved service configuration"))
  }

  override def createClient(body: dto.Client): F[dto.Client] = {
    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/client/create")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[dto.Client](request)
      .flatTap(resp =>
        logger.info(s"Successfully created client with client id ${resp.getClientId()} and client name ${resp.getClientName()}")
      )
  }

  override def dynamicClientRegister(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/registration"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[ClientRegistrationResponse](request)
      .flatTap(resp =>
        logger.info(s"ClientRegistration response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def dynamicClientGet(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/registration/get"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[ClientRegistrationResponse](request)
      .flatTap(resp =>
        logger.info(s"ClientRegistration response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def dynamicClientUpdate(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/registration/update"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[ClientRegistrationResponse](request)
      .flatTap(resp =>
        logger.info(s"ClientRegistration updated:  response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def dynamicClientDelete(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/registration/delete"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[ClientRegistrationResponse](request)
      .flatTap(resp =>
        logger.info(s"ClientRegistration deleted: response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def deleteClient(clientId: Long): F[Unit] =
    deleteClient(clientId.toString)

  override def deleteClient(clientId: String): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/delete/$clientId"
      )
    )
    val request = deleteRequest(uri)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(s"Client deleted successfully: $status")
        case status => logger.error(s"Failed to delete client: $status")
      }
  }

  override def getClient(clientId: Long): F[dto.Client] =
    getClient(clientId.toString)

  override def getClient(clientId: String): F[dto.Client] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/get/$clientId"
      )
    )
    val request = basicRequest(Method.GET, uri)
    client
      .expect[dto.Client](request)
      .flatTap(resp =>
        logger.info(s"Successfully retrieved client with client id ${resp.getClientId()} and client name ${resp.getClientName()}")
      )

  }

  override def getClientList(): F[ClientListResponse] =
    getClientList(None, 0, 0, false)

  override def getClientList(developer: String): F[ClientListResponse] =
    getClientList(Some(developer), 0, 0, false)

  override def getClientList(start: Int, end: Int): F[ClientListResponse] =
    getClientList(None, start, end, true)

  override def getClientList(
      developer: String,
      start: Int,
      end: Int
  ): F[ClientListResponse] =
    getClientList(Some(developer), start, end, true)

  override def getClientList(
      developer: Option[String],
      start: Int,
      end: Int,
      rangeGiven: Boolean
  ): F[ClientListResponse] = {
    val queryParams = Map(
      "developer" -> developer
    ).collect { case (k, Some(v)) => k -> v }
      .concat(
        if (rangeGiven)
          Map(
            "start" -> start.toString,
            "end"   -> end.toString
          )
        else Map.empty[String, String]
      )

    val uri = baseUri
      .withPath(Path.unsafeFromString(s"/api/${config.apiKey}/client/get/list"))
      .withQueryParams(queryParams)
    val request = basicRequest(Method.GET, uri)

    client
      .expect[ClientListResponse](request)
      .flatTap(resp => logger.info(s"Successfully retrieved client list"))

  }

  override def updateClient(body: dto.Client): F[dto.Client] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/client/update")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[dto.Client](request)
      .flatTap(resp =>
        logger.info(s"Successfully updated client with client id ${resp.getClientId()} and client name ${resp.getClientName()}")
      )

  }

  override def getRequestableScopes(clientId: Long): F[Array[String]] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/extension/requestable_scopes/get/$clientId"
      )
    )
    val request = basicRequest(Method.GET, uri)
    client
      .expect[Array[String]](request)
      .flatTap(resp =>
        logger.info(s"Successfully retrieved requestable scopes for client $clientId")
      )

  }

  override def setRequestableScopes(
      clientId: Long,
      scopes: Array[String]
  ): F[Array[String]] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/extension/requestable_scopes/set/$clientId"
      )
    )
    val request =
      basicRequest(Method.POST, uri).withEntity("requestableScopes" -> scopes)
    client
      .expect[Array[String]](request)
      .flatTap(resp => logger.info(s"Successfully set requestable scopes for client $clientId"))
  }

  override def deleteRequestableScopes(clientId: Long): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/extension/requestable_scopes/delete/$clientId"
      )
    )
    val request = deleteRequest(uri)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(s"Requestable scopes deleted successfully: $status")
        case status =>
          logger.error(s"Failed to delete requestable scopes: $status")
      }
  }

  override def getGrantedScopes(
      clientId: Long,
      subject: String
  ): F[GrantedScopesGetResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/extension/granted_scopes/get/$clientId"
      )
    )
    val request =
      basicRequest(Method.POST, uri).withEntity("subject" -> subject)
    client
      .expect[GrantedScopesGetResponse](request)
      .flatTap(resp =>
        logger.info(s"Successfully retrieved granted scopes for client $clientId and subject $subject with result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def deleteGrantedScopes(clientId: Long, subject: String): F[Unit] = {
    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/extension/granted_scopes/delete/$clientId"
      )
    )
    val request = postRequest(uri).withEntity("subject" -> subject)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(s"Granted scopes deleted successfully: $status")
        case status => logger.error(s"Failed to delete granted scopes: $status")
      }
  }

  override def deleteClientAuthorization(
      clientId: Long,
      subject: String
  ): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/authorization/delete/$clientId"
      )
    )
    val request = postRequest(uri).withEntity("subject" -> subject)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(
            s"Client authorization deleted successfully: $status for client $clientId and subject $subject"
          )
        case status =>
          logger.error(
            s"Failed to delete client authorization: $status for client $clientId and subject $subject"
          )
      }
  }

  override def getClientAuthorizationList(
      request: ClientAuthorizationGetListRequest
  ): F[AuthorizedClientListResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/authorization/get/list"
      )
    )
    val req = basicRequest(Method.POST, uri).withEntity(request)
    client
      .expect[AuthorizedClientListResponse](req)
      .flatTap(resp =>
        logger.info(
          s"Successfully retrieved client authorization list for subject ${resp.getSubject()}"
        )
      )

  }

  override def updateClientAuthorization(
      clientId: Long,
      body: ClientAuthorizationUpdateRequest
  ): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/authorization/update/$clientId"
      )
    )
    val req = basicRequest(Method.POST, uri).withEntity(body)
    client
      .status(req)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(
            s"Client authorization updated successfully: $status for client $clientId"
          )
        case status =>
          logger.error(
            s"Failed to update client authorization: $status for client $clientId"
          )
      }

  }

  override def refreshClientSecret(
      clientId: Long
  ): F[ClientSecretRefreshResponse] =
    refreshClientSecret(clientId.toString)

  override def refreshClientSecret(
      clientIdentifier: String
  ): F[ClientSecretRefreshResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/refresh/$clientIdentifier"
      )
    )
    val request = basicRequest(Method.POST, uri)
    client
      .expect[ClientSecretRefreshResponse](request)
      .flatTap(resp =>
        logger.info(s"Successfully refreshed client secret with result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def updateClientSecret(
      clientId: Long,
      clientSecret: String
  ): F[ClientSecretUpdateResponse] =
    updateClientSecret(clientId.toString, clientSecret)

  override def updateClientSecret(
      clientIdentifier: String,
      clientSecret: String
  ): F[ClientSecretUpdateResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/secret/update/$clientIdentifier"
      )
    )
    val request =
      basicRequest(Method.POST, uri).withEntity("clientSecret" -> clientSecret)
    client
      .expect[ClientSecretUpdateResponse](request)
      .flatTap(resp =>
        logger.info(s"Successfully updated client secret with result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def verifyJose(body: JoseVerifyRequest): F[JoseVerifyResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/jose/verify")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[JoseVerifyResponse](request)
      .flatTap(resp =>
        logger.info(s"Successfully verified JOSE with result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def backchannelAuthentication(
      body: BackchannelAuthenticationRequest
  ): F[BackchannelAuthenticationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/backchannel/authentication")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[BackchannelAuthenticationResponse](request)
      .flatTap(resp =>
        logger.info(s"BackchannelAuthentication response with action ${resp.getAction()},  result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def backchannelAuthenticationIssue(
      body: BackchannelAuthenticationIssueRequest
  ): F[BackchannelAuthenticationIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/backchannel/authentication/issue"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[BackchannelAuthenticationIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"BackchannelAuthenticationIssue response with  action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def backchannelAuthenticationFail(
      body: BackchannelAuthenticationFailRequest
  ): F[BackchannelAuthenticationFailResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/backchannel/authentication/fail"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[BackchannelAuthenticationFailResponse](request)
      .flatTap(resp =>
        logger.info(s"BackchannelAuthenticationFail response with  action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def backchannelAuthenticationComplete(
      body: BackchannelAuthenticationCompleteRequest
  ): F[BackchannelAuthenticationCompleteResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/backchannel/authentication/complete"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[BackchannelAuthenticationCompleteResponse](request)
      .flatTap(resp =>
        logger.info(s"BackchannelAuthenticationComplete response with  action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def deviceAuthorization(
      body: DeviceAuthorizationRequest
  ): F[DeviceAuthorizationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/device/authorization")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[DeviceAuthorizationResponse](request)
      .flatTap(resp =>
        logger.info(s"DeviceAuthorization response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def deviceComplete(
      body: DeviceCompleteRequest
  ): F[DeviceCompleteResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/device/complete")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[DeviceCompleteResponse](request)
      .flatTap(resp =>
        logger.info(s"DeviceComplete response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def deviceVerification(
      body: DeviceVerificationRequest
  ): F[DeviceVerificationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/device/verification")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[DeviceVerificationResponse](request)
      .flatTap(resp =>
        logger.info(s"DeviceVerification response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def pushAuthorizationRequest(
      body: PushedAuthReqRequest
  ): F[PushedAuthReqResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/pushed_auth_req")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[PushedAuthReqResponse](request)
      .flatTap(resp =>
        logger.info(s"PushedAuthReq response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def hskCreate(body: HskCreateRequest): F[HskResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/hsk/create")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[HskResponse](request)
      .flatTap(resp =>
        logger.info(s"Hsk create response with result action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def hskDelete(handle: String): F[HskResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/hsk/delete/$handle")
    )
    val request = deleteRequest(uri)
    client
      .expect[HskResponse](request)
      .flatTap(resp =>
        logger.info(s"Hsk delete response with  action ${resp.getAction()}, result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def hskGet(handle: String): F[HskResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/hsk/get/$handle")
    )
    val request = basicRequest(Method.GET, uri)
    client
      .expect[HskResponse](request)
      .flatTap(resp =>
        logger.info(s"Hsk get response with  action ${resp.getAction()}, result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def hskGetList(): F[HskListResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/hsk/get/list")
    )
    val request = basicRequest(Method.GET, uri)
    client
      .expect[HskListResponse](request)
      .flatTap(resp =>
        logger.info(s"HskList response with action ${resp.getAction()},result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def echo(parameters: Map[String, String]): F[Map[String, String]] = {
    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/echo")
    )
    val request = basicRequest(Method.GET, uri)
    client.expect[Map[String, String]](request)

  }

  override def gm(body: GMRequest): F[GMResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/gm")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[GMResponse](request)
      .flatTap(resp =>
        logger.info(s"GM response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def updateClientLockFlag(
      clientIdentifier: String,
      clientLocked: Boolean
  ): F[Unit] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/client/lock/$clientIdentifier/$clientLocked"
      )
    )
    val request = basicRequest(Method.POST, uri)
    client
      .status(request)
      .flatMap {
        case status if status.isSuccess =>
          logger.info(
            s"Client lock flag updated successfully: $status for client $clientIdentifier"
          )
        case status =>
          logger.error(
            s"Failed to update client lock flag: $status for client $clientIdentifier"
          )
      }
  }

  override def federationConfiguration(
      body: FederationConfigurationRequest
  ): F[FederationConfigurationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/federation/configuration")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[FederationConfigurationResponse](request)
      .flatTap(resp =>
        logger.info(s"FederationConfiguration response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def federationRegistration(
      body: FederationRegistrationRequest
  ): F[FederationRegistrationResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/federation/registration")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[FederationRegistrationResponse](request)
      .flatTap(resp =>
        logger.info(s"FederationRegistration response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def credentialIssuerMetadata(
      body: CredentialIssuerMetadataRequest
  ): F[CredentialIssuerMetadataResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/issuer/metadata")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialIssuerMetadataResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialIssueMetadata response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def credentialJwtIssuerMetadata(
      body: CredentialJwtIssuerMetadataRequest
  ): F[CredentialJwtIssuerMetadataResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/credential/jwt/issuer/metadata"
      )
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialJwtIssuerMetadataResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialJwtIssuerMetadata response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def credentialIssuerJwks(
      body: CredentialIssuerJwksRequest
  ): F[CredentialIssuerJwksResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/issuer/jwks")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialIssuerJwksResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialIssuerJwks response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def credentialOfferCreate(
      body: CredentialOfferCreateRequest
  ): F[CredentialOfferCreateResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/offer/create")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialOfferCreateResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialOfferCreate response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def credentialOfferInfo(
      body: CredentialOfferInfoRequest
  ): F[CredentialOfferInfoResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/offer/info")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialOfferInfoResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialOfferInfo response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialSingleParse(
      body: CredentialSingleParseRequest
  ): F[CredentialSingleParseResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/single/parse")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialSingleParseResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialSingleParse response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialSingleIssue(
      body: CredentialSingleIssueRequest
  ): F[CredentialSingleIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/single/issue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialSingleIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialSingleIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialBatchParse(
      body: CredentialBatchParseRequest
  ): F[CredentialBatchParseResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/batch/parse")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialBatchParseResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialBatchParse response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialBatchIssue(
      body: CredentialBatchIssueRequest
  ): F[CredentialBatchIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/batch/issue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialBatchIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialBatchIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialDeferredParse(
      body: CredentialDeferredParseRequest
  ): F[CredentialDeferredParseResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/deferred/parse")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialDeferredParseResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialDeferredParse response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def credentialDeferredIssue(
      body: CredentialDeferredIssueRequest
  ): F[CredentialDeferredIssueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/credential/deferred/issue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[CredentialDeferredIssueResponse](request)
      .flatTap(resp =>
        logger.info(s"CredentialDeferredIssue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def idTokenReissue(
      body: IDTokenReissueRequest
  ): F[IDTokenReissueResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/id_token/reissue")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[IDTokenReissueResponse](request)
      .flatTap(resp =>
        logger.info(s"IDTokenReissue response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def authorizationTicketInfo(
      body: AuthorizationTicketInfoRequest
  ): F[AuthorizationTicketInfoResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/ticket/info")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[AuthorizationTicketInfoResponse](request)
      .flatTap(resp =>
        logger.info(s"AuthorizationTicketInfo response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def authorizationTicketUpdate(
      body: AuthorizationTicketUpdateRequest
  ): F[AuthorizationTicketUpdateResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(s"/api/${config.apiKey}/auth/ticket/update")
    )
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[AuthorizationTicketUpdateResponse](request)
      .flatTap(resp =>
        logger.info(s"AuthorizationTicketUpdate response  with action ${resp.getAction()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )
  }

  override def tokenCreateBatch(
      body: Array[TokenCreateRequest],
      dryRun: Boolean
  ): F[TokenCreateBatchResponse] = {

    val uri = baseUri
      .withPath(
        Path.unsafeFromString(s"/api/${config.apiKey}/auth/token/create/batch")
      )
      .withQueryParam("dryRun", dryRun.toString)
    val request = basicRequest(Method.POST, uri).withEntity(body)
    client
      .expect[TokenCreateBatchResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenCreateBatch response  with request id ${resp.getRequestId()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

  override def getTokenCreateBatchStatus(
      requestId: String
  ): F[TokenCreateBatchStatusResponse] = {

    val uri = baseUri.withPath(
      Path.unsafeFromString(
        s"/api/${config.apiKey}/auth/token/create/batch/status/$requestId"
      )
    )
    val request = basicRequest(Method.GET, uri)
    client
      .expect[TokenCreateBatchStatusResponse](request)
      .flatTap(resp =>
        logger.info(s"TokenCreateBatchStatus response  with result ${resp.getStatus().getResult()} ,result code ${resp.getResultCode()} and message ${resp.getResultMessage()}")
      )

  }

}

object AuthleteServiceImpl {

  def apply[F[_]: Concurrent](
      client: HttpClient[F],
      config: AuthleteConfig,
      logger: Logger[F]
  ): F[AuthleteServiceImpl[F]] = Concurrent[F]
    .pure(new AuthleteServiceImpl[F](client, config, logger))

  def make[F[_]: Concurrent](
      client: HttpClient[F],
      config: AuthleteConfig,
      logger: Logger[F]
  ): Resource[F, AuthleteServiceImpl[F]] = apply(client, config, logger).toResource

}
