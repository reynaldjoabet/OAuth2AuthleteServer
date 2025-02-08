package routes

import java.net.URLEncoder

import scala.jdk.CollectionConverters.*

import cats.effect.kernel.Async
import cats.syntax.all.*

import com.authlete.common.dto.AuthorizationIssueRequest
import com.authlete.common.dto.AuthorizationIssueResponse
import com.authlete.common.dto.AuthorizationRequest
import com.authlete.common.dto.AuthorizationResponse
import com.authlete.common.dto.DynamicScope
import com.authlete.common.dto.Scope
import com.authlete.common.web.*
import domain.AuthorizationPage
import domain.User
import io.circe.syntax.*
import org.http4s.*
import org.http4s.dsl.Http4sDsl
import services.*
import services.AuthleteService

//https://www.authlete.com/developers/definitive_guide/authorization_endpoint_impl/
final case class AuthorizationRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  /**
    * Authorization endpoint which supports OAuth 2&#x2E;0 and OpenID Connect.
    *
    * @see
    *   <a href="http://tools.ietf.org/html/rfc6749#section-3.1" >RFC 6749, 3.1. Authorization
    *   Endpoint</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint" >OpenID
    *   Connect Core 1.0, 3.1.2. Authorization Endpoint (Authorization Code Flow)</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthorizationEndpoint"
    *   >OpenID Connect Core 1.0, 3.2.2. Authorization Endpoint (Implicit Flow)</a>
    *
    * @see
    *   <a href="http://openid.net/specs/openid-connect-core-1_0.html#HybridAuthorizationEndpoint"
    *   >OpenID Connect Core 1.0, 3.3.2. Authorization Endpoint (Hybrid Flow)</a>
    */
  val routes: HttpRoutes[F] = HttpRoutes.of[F] {
    /**
      * The authorization endpoint for {@@@@@@@@codeGET} method.
      *
      * <p> <a href="http://tools.ietf.org/html/rfc6749#section-3.1">RFC 6749, 3.1 Authorization
      * Endpoint</a> says that the authorization endpoint MUST support {@@@@@@@@codeGET} method.
      * </p>
      *
      * @see
      *   <a href="http://tools.ietf.org/html/rfc6749#section-3.1" >RFC 6749, 3.1 Authorization
      *   Endpoint</a>
      */
    case req @ GET -> Root / "authorization" =>
      val parameters = req
        .params
        .map { case (key, value) =>
          s"$key=$value"
        }
        .mkString("&")
      val authorizationRequest: AuthorizationRequest = AuthorizationRequest()
        .setParameters(parameters)

      processAuthorizationResponse(authorizationRequest)
      Ok("Hello, World!")

    /**
      * The authorization endpoint for {@@@@@@@@codePOST} method.
      *
      * <p> <a href="http://tools.ietf.org/html/rfc6749#section-3.1">RFC 6749, 3.1 Authorization
      * Endpoint</a> says that the authorization endpoint MAY support {@@@@@@@@codePOST} method.
      * </p>
      *
      * <p> In addition, <a href= "http://openid.net/specs/openid-connect-core-1_0.html#AuthRequest"
      * >OpenID Connect Core 1.0, 3.1.2.1. Authentication Request</a> says that the authorization
      * endpoint MUST support {@@@@@@@@codePOST} method. </p>
      */
    case req @ POST -> Root / "authorization" =>
      req
        .as[UrlForm]
        .flatMap { form =>
          val parameters = form.values.map((k, v) => (k, v.toVector.toArray)).asJava
          // .map { case (key, value) =>
          //   s"${URLEncoder.encode(key, "UTF-8")}=${URLEncoder.encode(value, "UTF-8")}"
          // }
          // .mkString("&")

        val authorizationRequest: AuthorizationRequest = AuthorizationRequest()
          .setParameters(URLCoder.formUrlEncode(parameters))

        processAuthorizationResponse(authorizationRequest)
        }

  }

  private def processAuthorizationResponse(body: AuthorizationRequest) =
    authleteService
      .authorization(body)
      .flatMap { resp =>
        val content = resp.getResponseContent()
        resp.getAction() match {
          // 500 Internal Server Error
          case AuthorizationResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError(content)

          // 400 Bad Request
          case AuthorizationResponse.Action.BAD_REQUEST => Status.BadRequest(content)
          case AuthorizationResponse.Action.LOCATION    => Status.Found(content) // 302 Found

          // 200 OK
          /**
            * Create a response of {@code "200 OK"} with the given entity formatted in
            * {@code "text/html;charset=UTF-8"} .
            */
          case AuthorizationResponse.Action.FORM => ???
          // Process the authorization request without user interaction.
          // The flow reaches here only when the authorization request
          // contained prompt=none.

          case AuthorizationResponse.Action.NO_INTERACTION =>
            val authorizationIssueRequest: AuthorizationIssueRequest = AuthorizationIssueRequest()
            handleNoInteraction(authorizationIssueRequest)

          // Process the authorization request with user interaction.
          case AuthorizationResponse.Action.INTERACTION =>
            handleInteraction(resp)
        }
      }

    /**
      * Create an {@link AuthorizationPageModel} instance using information contained in an
      * {@link AuthorizationResponse} object
      */

    /**
      * Handle the case where {@code action} parameter in a response from Authlete's
      * {@code /api/auth/authorization} API is {@code INTERACTION} .
      */
    //    private Response handleInteraction(AuthorizationResponse response)
    //    {
    //        return mSpi.generateAuthorizationPage(response);
    //    }

  private def handleInteraction(resp: AuthorizationResponse): F[Response[F]] = {

    // Get the user from the session if they exist.
    // User user = (User)session.getAttribute("user");
    val user: User               = ???
    val client                   = resp.getClient()
    val serviceName              = resp.getService().getServiceName()
    val clientName               = client.getClientName()
    val description              = Option(client.getDescription())
    val logoUri                  = Option(client.getLogoUri().toString())
    val clientUri                = Option(client.getClientUri().toString())
    val policyUri                = Option(client.getPolicyUri().toString())
    val tosUri                   = Option(client.getTosUri().toString())
    val scopes                   = computeScopes(resp)
    val loginId                  = computeLoginId(resp)
    val loginIdReadOnly          = Option(resp.getSubject()) // computeLoginIdReadOnly(resp)
    val authorizationDetails     = resp.getAuthorizationDetails().asJson.noSpaces
    val purpose                  = Option(resp.getPurpose())
    val verifiedClaimsForIdToken = resp.getIdTokenClaims()
    // For "OpenID Connect for Identity Assurance 1.0"
    // setupIdentityAssurance(info);

    // Requested normal claims.
    val claimsForIdToken  = resp.getClaims();
    val claimsForUserInfo = resp.getClaimsAtUserInfo();

    val authorizationPage = AuthorizationPage(
      serviceName,
      clientName,
      description,
      logoUri,
      clientUri,
      policyUri,
      tosUri,
      scopes,
      loginId,
      loginIdReadOnly,
      user,
      authorizationDetails,
      purpose,
      verifiedClaimsForIdToken = Array.empty,
      allVerifiedClaimsForIdTokenRequested = None,
      verifiedClaimsForUserInfo = Array.empty,
      allVerifiedClaimsForUserInfoRequested = None,
      identityAssuranceRequired = None,
      oldIdaFormatUsed = None,
      claimsForIdToken,
      claimsForUserInfo
    )

    // generateAuthorizationPage
    ???
  }

  private def handleNoInteraction(body: AuthorizationIssueRequest): F[Response[F]] =
    authleteService
      .authorizationIssue(body)
      .flatMap { resp =>
        resp.getAction() match {
          case AuthorizationIssueResponse.Action.INTERNAL_SERVER_ERROR =>
            Status.InternalServerError()
          case AuthorizationIssueResponse.Action.BAD_REQUEST => Status.BadRequest()
          case AuthorizationIssueResponse.Action.LOCATION    => Status.TemporaryRedirect(???) // Status.Redirection// Status.SeeOther()//Status.PermanentRedirect(???)
          case AuthorizationIssueResponse.Action.FORM        => ???
        }
      }

    /**
      * Build the list of scopes to display.
      */

  private def computeScopes(resp: AuthorizationResponse): Array[Scope] = {
    val scopes: Array[Scope] = resp.getScopes()

    val dynamicScopes: Option[Array[DynamicScope]] = Option(resp.getDynamicScopes())

    // If the authorization request does not contain dynamic scopes.
    dynamicScopes
      .map { dScopes =>
        scopes ++ dScopes.map(ds => new Scope().setName(ds.getValue()))
      }
      // No need to convert dynamic scopes to scopes, so the value of
      // the "scopes" response parameter are used without modification.
      .getOrElse(scopes)

  }

  /**
    * Compute the initial value for the login ID field in the authorization page.
    */

  private def computeLoginId(resp: AuthorizationResponse): String =
    Option(resp.getSubject).getOrElse(resp.getLoginHint)

  /**
    * Return {@code "readonly"} if the authorization request requires that a specific subject be
    * used.
    */
  private def computeLoginIdReadOnly(resp: AuthorizationResponse): Option[String] = Option(
    resp.getSubject()
  )

}
