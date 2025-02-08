package services

import cats.effect.Concurrent
import cats.syntax.all.*

import com.authlete.common.api.*
import com.authlete.common.api.Options
import com.authlete.common.api.Settings
import com.authlete.common.dto
import com.authlete.common.dto.*
import com.authlete.common.types.TokenStatus
import config.AuthleteConfig
import org.checkerframework.checker.units.qual.g
import org.http4s.circe.CirceEntityCodec.*
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

abstract class AuthleteService[F[_]] {

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/authorization} API.
    */
  def authorization(body: AuthorizationRequest): F[AuthorizationResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/authorization/fail} API.
    */
  def authorizationFail(
      body: AuthorizationFailRequest
  ): F[AuthorizationFailResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/authorization/issue} API.
    */
  def authorizationIssue(
      body: AuthorizationIssueRequest
  ): F[AuthorizationIssueResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token} API.
    */
  def token(body: TokenRequest): F[TokenResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token/create} API.
    */
  def tokenCreate(body: TokenCreateRequest): F[TokenCreateResponse]

  /**
    * Call <code>/api/{serviceId}/auth/token/delete/<i>{token}</i></code> API.
    */
  def tokenDelete(token: String): F[Unit]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token/fail} API.
    */
  def tokenFail(body: TokenFailRequest): F[TokenFailResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token/issue} API.
    */
  def tokenIssue(body: TokenIssueRequest): F[TokenIssueResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token/revoke} API.
    */
  def tokenRevoke(body: TokenRevokeRequest): F[TokenRevokeResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/token/update} API.
    */
  def tokenUpdate(body: TokenUpdateRequest): F[TokenUpdateResponse]

  def getTokenList(): F[TokenListResponse]

  def getTokenList(tokenStatus: TokenStatus): F[TokenListResponse]

  def getTokenList(
      clientIdentifier: String,
      subject: String
  ): F[TokenListResponse]

  def getTokenList(
      clientIdentifier: String,
      subject: String,
      tokenStatus: TokenStatus
  ): F[TokenListResponse]

  def getTokenList(start: Int, end: Int): F[TokenListResponse]

  def getTokenList(
      start: Int,
      end: Int,
      tokenStatus: TokenStatus
  ): F[TokenListResponse]

  def getTokenList(
      clientIdentifier: String,
      subject: String,
      start: Int,
      end: Int
  ): F[TokenListResponse]

  def getTokenList(
      clientIdentifier: Option[String],
      subject: Option[String],
      start: Int,
      end: Int,
      rangeGiven: Boolean,
      tokenStatus: TokenStatus
  ): F[TokenListResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/revocation} API.
    */
  def revocation(body: RevocationRequest): F[RevocationResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/userinfo} API.
    */
  def userinfo(body: UserInfoRequest): F[UserInfoResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/userinfo/issue} API.
    */
  def userinfoIssue(body: UserInfoIssueRequest): F[UserInfoIssueResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/introspection} API.
    */
  def introspection(body: IntrospectionRequest): F[IntrospectionResponse]

  /**
    * Call {@@@@@@@@@@@code/api/{serviceId} /auth/introspection/standard} API.
    */
  def standardIntrospection(
      body: StandardIntrospectionRequest
  ): F[StandardIntrospectionResponse]

  /**
    * Call {@@@@@@@@@@@code/api/service/create} API.
    */
  def createService(service: Service): F[Service]

  @deprecated("Use createService instead")
  def createServie(service: Service): F[Service]

  /**
    * Call <code>/api/{serviceId}/service/delete/</code> API.
    */
  def deleteService(): F[Unit]

  /**
    * Call <code>/api/{serviceId}/service/get</i></code> API.
    */
  def getService(): F[Service]

  /**
    * Call {@@@@@@@@@code/api/service/get/list} API.
    */
  def getServiceList(): F[ServiceListResponse]

  def getServiceList(start: Int, end: Int): F[ServiceListResponse]

  def getServiceList(
      start: Int,
      end: Int,
      rangeGiven: Boolean
  ): F[ServiceListResponse]

  /**
    * Call <code>/api/{serviceId}/service/update/</code> API.
    */
  def updateService(service: Service): F[Service]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /service/jwks/get} API
    */
  def getServiceJwks(): F[String]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /service/jwks/get} API
    */
  def getServiceJwks(pretty: Boolean, includePrivateKeys: Boolean): F[String]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /service/configuration} API
    */
  def getServiceConfiguration(): F[String]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /service/configuration} API
    */
  def getServiceConfiguration(pretty: Boolean): F[String]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /service/configuration} API
    */
  def getServiceConfiguration(body: ServiceConfigurationRequest): F[String]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/create} API.
    */
  def createClient(body: Client): F[Client]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/registration} API.
    */
  def dynamicClientRegister(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/registration/get} API.
    */
  def dynamicClientGet(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/registration/update} API.
    */
  def dynamicClientUpdate(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/registration/delete} API.
    */
  def dynamicClientDelete(
      body: ClientRegistrationRequest
  ): F[ClientRegistrationResponse]

  /**
    * Call <code>/api/{serviceId}/client/delete/<i>{clientId}</i></code> API.
    */
  def deleteClient(clientId: Long): F[Unit]

  /**
    * Call <code>/api/{serviceId}/client/delete/<i>{clientId}</i></code> API.
    */
  def deleteClient(clientId: String): F[Unit]

  /**
    * Call <code>/api/{serviceId}/client/get/<i>{clientId}</i></code> API.
    */
  def getClient(clientId: Long): F[Client]

  /**
    * Call <code>/api/{serviceId}/client/get/<i>{clientId}</i></code> API.
    */
  def getClient(clientId: String): F[Client]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /client/get/list} API.
    */
  def getClientList(): F[ClientListResponse]

  def getClientList(developer: String): F[ClientListResponse]

  def getClientList(start: Int, end: Int): F[ClientListResponse]

  def getClientList(
      developer: String,
      start: Int,
      end: Int
  ): F[ClientListResponse]

  def getClientList(
      developer: Option[String],
      start: Int,
      end: Int,
      rangeGiven: Boolean
  ): F[ClientListResponse]

  /**
    * Call <code>/api/{serviceId}/client/update/<i>{clientId}</i></code> API.
    */
  def updateClient(body: Client): F[Client]

  /**
    * Call <code>/api/{serviceId}/client/extension/requestable_scopes/get/<i>{clientId}</i></code>
    * API.
    */
  def getRequestableScopes(clientId: Long): F[Array[String]]

  def setRequestableScopes(
      clientId: Long,
      scopes: Array[String]
  ): F[Array[String]]

  /**
    * Call
    * <code>/api/{serviceId}/client/extension/requestable_scopes/delete/<i>{clientId}</i></code>
    * API.
    */
  def deleteRequestableScopes(clientId: Long): F[Unit]

  def getGrantedScopes(
      clientId: Long,
      subject: String
  ): F[GrantedScopesGetResponse]

  def deleteGrantedScopes(clientId: Long, subject: String): F[Unit]

  def deleteClientAuthorization(clientId: Long, subject: String): F[Unit]

  def getClientAuthorizationList(
      request: ClientAuthorizationGetListRequest
  ): F[AuthorizedClientListResponse]

  def updateClientAuthorization(
      clientId: Long,
      request: ClientAuthorizationUpdateRequest
  ): F[Unit]

  def refreshClientSecret(clientId: Long): F[ClientSecretRefreshResponse]

  def refreshClientSecret(
      clientIdentifier: String
  ): F[ClientSecretRefreshResponse]

  def updateClientSecret(
      clientId: Long,
      clientSecret: String
  ): F[ClientSecretUpdateResponse]

  def updateClientSecret(
      clientIdentifier: String,
      clientSecret: String
  ): F[ClientSecretUpdateResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /jose/verify} API.
    */
  def verifyJose(body: JoseVerifyRequest): F[JoseVerifyResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /backchannel/authentication} API.
    */
  def backchannelAuthentication(
      body: BackchannelAuthenticationRequest
  ): F[BackchannelAuthenticationResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /backchannel/authentication/issue} API.
    */
  def backchannelAuthenticationIssue(
      body: BackchannelAuthenticationIssueRequest
  ): F[BackchannelAuthenticationIssueResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /backchannel/authentication/fail} API.
    */
  def backchannelAuthenticationFail(
      body: BackchannelAuthenticationFailRequest
  ): F[BackchannelAuthenticationFailResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /backchannel/authentication/complete} API.
    */
  def backchannelAuthenticationComplete(
      body: BackchannelAuthenticationCompleteRequest
  ): F[BackchannelAuthenticationCompleteResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /device/authorization} API.
    */
  def deviceAuthorization(
      body: DeviceAuthorizationRequest
  ): F[DeviceAuthorizationResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /device/complete} API.
    */
  def deviceComplete(body: DeviceCompleteRequest): F[DeviceCompleteResponse]

  /**
    * Call {@@@@@@@@@code/api/{serviceId} /device/verification} API.
    */
  def deviceVerification(
      body: DeviceVerificationRequest
  ): F[DeviceVerificationResponse]

  def pushAuthorizationRequest(
      body: PushedAuthReqRequest
  ): F[PushedAuthReqResponse]

  def hskCreate(body: HskCreateRequest): F[HskResponse]

  def hskDelete(handle: String): F[HskResponse]

  def hskGet(handle: String): F[HskResponse]

  def hskGetList(): F[HskListResponse]

  def echo(parameters: Map[String, String]): F[Map[String, String]]

  def gm(body: GMRequest): F[GMResponse]

  def updateClientLockFlag(
      clientIdentifier: String,
      clientLocked: Boolean
  ): F[Unit]

  def federationConfiguration(
      body: FederationConfigurationRequest
  ): F[FederationConfigurationResponse]

  def federationRegistration(
      body: FederationRegistrationRequest
  ): F[FederationRegistrationResponse]

  def credentialIssuerMetadata(
      body: CredentialIssuerMetadataRequest
  ): F[CredentialIssuerMetadataResponse]

  def credentialJwtIssuerMetadata(
      body: CredentialJwtIssuerMetadataRequest
  ): F[CredentialJwtIssuerMetadataResponse]

  def credentialIssuerJwks(
      body: CredentialIssuerJwksRequest
  ): F[CredentialIssuerJwksResponse]

  def credentialOfferCreate(
      body: CredentialOfferCreateRequest
  ): F[CredentialOfferCreateResponse]

  def credentialOfferInfo(
      body: CredentialOfferInfoRequest
  ): F[CredentialOfferInfoResponse]

  def credentialSingleParse(
      body: CredentialSingleParseRequest
  ): F[CredentialSingleParseResponse]

  def credentialSingleIssue(
      body: CredentialSingleIssueRequest
  ): F[CredentialSingleIssueResponse]

  def credentialBatchParse(
      body: CredentialBatchParseRequest
  ): F[CredentialBatchParseResponse]

  def credentialBatchIssue(
      body: CredentialBatchIssueRequest
  ): F[CredentialBatchIssueResponse]

  def credentialDeferredParse(
      body: CredentialDeferredParseRequest
  ): F[CredentialDeferredParseResponse]

  def credentialDeferredIssue(
      body: CredentialDeferredIssueRequest
  ): F[CredentialDeferredIssueResponse]

  def idTokenReissue(body: IDTokenReissueRequest): F[IDTokenReissueResponse]

  def authorizationTicketInfo(
      body: AuthorizationTicketInfoRequest
  ): F[AuthorizationTicketInfoResponse]

  def authorizationTicketUpdate(
      body: AuthorizationTicketUpdateRequest
  ): F[AuthorizationTicketUpdateResponse]

  def tokenCreateBatch(
      body: Array[TokenCreateRequest],
      dryRun: Boolean
  ): F[TokenCreateBatchResponse]

  def getTokenCreateBatchStatus(
      requestId: String
  ): F[TokenCreateBatchStatusResponse]

}
