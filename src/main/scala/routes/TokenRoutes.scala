package routes

import java.net.URI

import scala.jdk.CollectionConverters.*

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.TokenCreateRequest
import com.authlete.common.dto.TokenCreateResponse
import com.authlete.common.dto.TokenFailRequest
import com.authlete.common.dto.TokenFailResponse
import com.authlete.common.dto.TokenIssueRequest
import com.authlete.common.dto.TokenIssueResponse
import com.authlete.common.dto.TokenRequest
import com.authlete.common.dto.TokenResponse
import com.authlete.common.types.GrantType
import com.authlete.common.types.TokenType
import com.nimbusds.jwt.EncryptedJWT
import com.nimbusds.jwt.JWTParser
import domain.SessionUser
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.`WWW-Authenticate`
import org.http4s.headers.Authorization
import org.http4s.syntax.header
import org.http4s.Credentials.AuthParams
import org.http4s.Credentials.Token
import org.typelevel.ci.*
import services.*
import services.AuthleteService
import services.DpopService.*

/**
  * To prevent token scanning attacks, the endpoint MUST also require some form of authorization to
  * access this endpoint, such as client authentication as described in OAuth 2.0 [RFC 6749] or a
  * separate OAuth 2.0 access token such as the bearer token described in OAuth 2.0 Bearer Token
  * Usage [RFC 6750]. The methods of managing and validating these authentication credentials are
  * out of scope of this specification.
  *
  * @param authleteService
  */
final case class TokenRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  /**
    * Token endpoint which supports OAuth 2&#x2E;0 and OpenID Connect.
    *
    * @see
    *   <a href="http://tools.ietf.org/html/rfc6749#section-3.2" >RFC 6749, 3.2. Token Endpoint</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridTokenEndpoint" >OpenID
    *   Connect Core 1.0, 3.3.3. Token Endpoint</a>
    */

  val routes = AuthedRoutes.of[SessionUser, F] {
    /**
      * The token endpoint for {@@@@@@@@codePOST} method.
      *
      * <p> <a href="http://tools.ietf.org/html/rfc6749#section-3.2">RFC 6749, 3.2. Token
      * Endpoint</a> says: </p>
      *
      * <blockquote> <i>The client MUST use the HTTP "POST" method when making access token
      * requests.</i> </blockquote>
      *
      * <p> <a href="http://tools.ietf.org/html/rfc6749#section-2.3">RFC 6749, 2.3. Client
      * Authentication</a> mentions (1) HTTP Basic Authentication and (2) {@@@@@@@@codeclient_id}
      * &amp; {@@@@@@@@codeclient_secret} parameters in the request body as the means of client
      * authentication. This implementation supports the both means. </p>
      *
      * @see
      *   <a href="http://tools.ietf.org/html/rfc6749#section-3.2" >RFC 6749, 3.2. Token
      *   Endpoint</a>
      */
    case req @ POST -> Root / "token" as session =>
      req
        .req
        .as[UrlForm]
        .flatMap { form =>

          val parameters = form
            .values
            .collect { case (k, v) if !k.isBlank() => (k, v.toList.toArray) }
            .asJava

          // RFC 6749
          // The OAuth 2.0 Authorization Framework

          val basicCredentials = extractClientCredentialFromAuthorization(req.req)

          basicCredentials.fold(
            Status.Unauthorized(
              `WWW-Authenticate`(Challenge("Bearer", "realm", Map("charset" -> "UTF-8")))
            )
          ) { cred =>

            // MTLS
            // RFC 8705 : OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens
            val clientCertificatePath = Array[String]() // extractClientCertificateChain(req)

            val clientCertificate = extractClientCertificate(clientCertificatePath)
          // DPoP
          // OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (DPoP)

          val dpop = extractDpopProof(req.req).toOption

          // params.setDpop(request.getHeader("DPoP"))
          //       .setHtm("POST")
          //       //.setHtu(request.getRequestURL().toString())

// We can reconstruct the URL of the token endpoint by calling
// request.getRequestURL().toString() and set it to params by the
// setHtu(String) method. However, the calculated URL may be invalid
// behind proxies.
//
// If "htu" is not set here, the "tokenEndpoint" property of "Service"
// (which can be configured by using Authlete's Service Owner Console)
// is referred to as the default value. Therefore, we don't call the
// setHtu(String) method here intentionally. Note that this means you
// have to set "tokenEndpoint" properly to support DPoP.

// Even the call of the setHtm(String) method can be omitted, too.
// When "htm" is not set, "POST" is used as the default value.

// OAuth 2.0 Attestation-Based Client Authentication
          val clientAttestation    = extractClientAttestation(req.req)
          val clientAttestationPop = extractClientAttestationPop(req.req)

          lazy val tokenRequest: TokenRequest = TokenRequest()
            .setParameters(parameters)
            .setClientId(cred.username)
            .setClientSecret(cred.password)
            // .setProperties(properties)
            .setClientCertificate(clientCertificate.orNull)
            // .setClientCertificatePath(clientCertificatePath)
            .setDpop(dpop.orNull)
            .setHtm("POST")
            // .setHtu(htu)
            .setOauthClientAttestation(clientAttestation.orNull)
            .setOauthClientAttestationPop(clientAttestationPop.orNull)

          processTokenResponse(tokenRequest)

          }
        }
  }

  private def processTokenIssueResponse(
      body: TokenIssueRequest,
      respHeaders: Headers
  ): F[Response[F]] =
    authleteService
      .tokenIssue(body)
      .flatMap { resp =>
        resp.getAction() match {
          case TokenIssueResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError(resp.getResponseContent(), respHeaders)
          case TokenIssueResponse.Action.OK => ???
        }

      }

  private def processTokenFailResponse(
      body: TokenFailRequest,
      respHeaders: Headers
  ): F[Response[F]] =
    authleteService
      .tokenFail(body)
      .flatMap { resp =>
        resp.getAction() match {
          case TokenFailResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError(resp.getResponseContent(), respHeaders)
          case TokenFailResponse.Action.BAD_REQUEST =>
            Status.BadRequest(resp.getResponseContent(), respHeaders)
        }
      }

  private def processTokenResponse(
      body: TokenRequest
  ): F[Response[F]] =
    authleteService
      .token(body)
      .flatMap { resp =>
        val content                  = resp.getResponseContent()
        val dpopNonceHeader          = Option(resp.getDpopNonce()).map(Header.Raw(ci"DPoP-Nonce", _))
        val responseHeaders: Headers = dpopNonceHeader.map(Headers(_)).getOrElse(Headers.empty)
        resp.getAction() match {
          case TokenResponse.Action.INVALID_CLIENT =>
            Status.BadRequest(content, responseHeaders)

          case TokenResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError(content, responseHeaders)

          case TokenResponse.Action.BAD_REQUEST =>
            Status.BadRequest(content, responseHeaders)
          case TokenResponse.Action.PASSWORD =>
            // validate the credentials of the resource owner and call  Authlete's /auth/token/issue API or  /auth/token/fail
            lazy val tokenIssueRequest: TokenIssueRequest = TokenIssueRequest()
              .setSubject(resp.getSubject())
              .setTicket(resp.getTicket())

            lazy val tokenFailRequest: TokenFailRequest = TokenFailRequest()

            Async[F]
              .ifM(Async[F].delay(true))(
                processTokenIssueResponse(tokenIssueRequest, responseHeaders),
                processTokenFailResponse(tokenFailRequest, responseHeaders)
              )
              .map { res =>
                dpopNonceHeader.fold(res)(header => res.putHeaders(header))
              }

          case TokenResponse.Action.OK =>
            Ok(resp.getAccessToken(), responseHeaders)
          case TokenResponse.Action.TOKEN_EXCHANGE =>
            //   // Process the token exchange request (RFC 8693)
            handleTokenExchange(resp, responseHeaders)

          case TokenResponse.Action.JWT_BEARER =>
            //   // Process the token request which uses the grant type
            //   // urn:ietf:params:oauth:grant-type:jwt-bearer (RFC 7523).
            handleJwtBearer(resp, responseHeaders)

          case TokenResponse.Action.ID_TOKEN_REISSUABLE =>
            //   // The flow of the token request is the refresh token flow
            //   // and an ID token can be reissued.
            handleIdTokenReissuable(resp, responseHeaders)
        }
      }

  private def handleTokenExchange(resp: TokenResponse, headers: Headers): F[Response[F]] =
    TokenExchanger.createResponse(resp, authleteService).getOrElse(Status.BadRequest())

  private def handleJwtBearer(resp: TokenResponse, headers: Headers): F[Response[F]] =
    JwtAuthzGrantProcessor.createResponse(resp, authleteService).getOrElse(Status.BadRequest())

  private def handleIdTokenReissuable(resp: TokenResponse, headers: Headers): F[Response[F]] = ???

  // The credential of the client application extracted from the
  // Authorization header. If available, the first element is the
  // client ID and the second element is the client secret.
  private def extractClientCredentialFromAuthorization(req: Request[F]) =
    req
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

  private def extractClientCertificate(clientCertificatePath: Array[String]): Option[String] =
    // A client certificate is unavailable.(None)
    Option(clientCertificatePath).flatMap(path => if (path.isEmpty) None else Some(path(0))) // The first one in the certificate path is the client's certificate.

  private def extractSubsequenceFromClientCertificatePath(
      clientCertificatePath: Array[String]
  ): Option[Array[String]] =
    Option(clientCertificatePath).flatMap(path => if (path.isEmpty) None else Some(path.tail)) // Extract the second and subsequent elements. (= Remove the first element.)

}
