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

import cats.Show
import cats.syntax.show.*

import org.http4s.EntityEncoder
import cats.effect.{Concurrent}
import cats.MonadThrow
import org.http4s.circe.*
import io.circe.Decoder
import org.http4s.EntityDecoder
import cats.MonadThrow
import org.http4s.MediaType
import org.http4s.circe.middleware.JsonDebugErrorHandler
//import org.http4s.EntityDecoder.*
import org.http4s.circe.CirceEntityCodec.circeEntityDecoder
import io.circe.parser
//   import org.http4s.circe.CirceEntityDecoder.circeEntityDecoder
import io.circe.generic.auto.deriveDecoder
import cats.syntax.all.*
import org.http4s.DecodeResult
import org.http4s.InvalidMessageBodyFailure
import io.circe.Encoder
import cats.effect.kernel.Async
import io.circe.jawn
import org.http4s.MalformedMessageBodyFailure
import io.circe.Json
import com.authlete.common.dto.AuthzDetailsElement

/** Convert Authlete DTOs to strings. Implementations in this class MUST NOT
  * output the secrets. Currently, `subject` will not be output since it can be
  * a actual name.
  */
object AuthleteClientUtils {

  def AuthleteClientUtilsHelper[A](getters: A => (String, String)*): Show[A] =
    self => self.getClass.getName + getters.map(g => g(self)).toMap.show

  implicit val showApiResponse: Show[ApiResponse] =
    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage
    )

  implicit val showClient: Show[Client] =
    AuthleteClientUtilsHelper(
      "ClientId" -> _.getClientId.show,
      "ClientName" -> _.getClientName
    )

  implicit val showAuthorizationRequest: Show[AuthorizationRequest] =
    // `parameters` can contain sensitives like pkce challenge
    AuthleteClientUtilsHelper()

  implicit val showAuthorizationResponse: Show[AuthorizationResponse] = {
    implicit val showAction: Show[AuthorizationResponse.Action] = fromToString
    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      x => "Action" -> x.getAction.show
    )
  }

  implicit val showAuthorizationIssueRequest: Show[AuthorizationIssueRequest] =
    AuthleteClientUtilsHelper()

  implicit val showAuthorizationIssueResponse
      : Show[AuthorizationIssueResponse] = {

    implicit val showAction: Show[AuthorizationIssueResponse.Action] =
      Show.show((action: AuthorizationIssueResponse.Action) => action.toString)

    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action" -> _.getAction.show
    )
  }

  implicit val showAuthorizationFailResponse
      : Show[AuthorizationFailResponse] = {
    implicit val showAction: Show[AuthorizationFailResponse.Action] =
      Show.show((action: AuthorizationFailResponse.Action) => action.toString)
    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action" -> _.getAction.show
    )
  }

  implicit val showTokenRequest: Show[TokenRequest] = {
    AuthleteClientUtilsHelper(
      "ClientId" -> _.getClientId
    )
  }

  implicit val showTokenResponse: Show[TokenResponse] = {
    implicit val showAction: Show[TokenResponse.Action] =
      Show.show((action: TokenResponse.Action) => action.toString)

    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action" -> _.getAction.show,
      "ClientId" -> _.getClientId.show
    )
  }

  implicit val showIntrospectionRequest: Show[IntrospectionRequest] = {
    AuthleteClientUtilsHelper()
  }

  implicit val showIntrospectionResponse: Show[IntrospectionResponse] = {
    implicit val showAction: Show[IntrospectionResponse.Action] = fromToString
    AuthleteClientUtilsHelper(
      "ResultCode" -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action" -> _.getAction.show,
      "ClientId" -> _.getClientId.show
    )
  }

  implicit val showRevocationRequest: Show[RevocationRequest] = {
    AuthleteClientUtilsHelper("ClientId" -> _.getClientId)
  }

  def fromToString[A]: Show[A] = _.toString

  implicit val showRevocationResponse: Show[RevocationResponse] = {
    implicit val showAction: Show[RevocationResponse.Action] = fromToString
    AuthleteClientUtilsHelper(
      "ResultMessage" -> _.getResultMessage,
      "Action" -> _.getAction.show
    )
  }

  implicit val showAuthorizationFailRequest: Show[AuthorizationFailRequest] = {
    implicit val showReason: Show[AuthorizationFailRequest.Reason] =
      fromToString
    AuthleteClientUtilsHelper(
      "Ticket" -> _.getTicket,
      "Reason" -> _.getReason.show,
      "description" -> _.getDescription
    )
  }

  implicit val encoderRevocationRequest: Encoder[RevocationRequest] =
    Encoder.instance[RevocationRequest] { a =>
      Json.obj(
        "parameters" -> Json.fromString(a.getParameters()),
        "clientId" -> Json.fromString(a.getClientId()),
        "clientSecret" -> Json.fromString(a.getClientSecret()),
        "clientCertificate" -> Json.fromString(a.getClientCertificate()),
        "clientCertificatePath" -> Json.arr(
          a.getClientCertificatePath().map(Json.fromString): _*
        ),
        "oauthClientAttestation" -> Json.fromString(
          a.getOauthClientAttestation()
        ),
        "oauthClientAttestationPop" -> Json.fromString(
          a.getOauthClientAttestationPop()
        )
      )
    }

  implicit val decoderRevocationResponse: Decoder[RevocationResponse] =
    Decoder.instance { h =>
      for {
        resultCode <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultMessage")
        action <- h.get[String]("action")
        responseContent <- h.get[String]("responseContent")

      } yield {
        var response = RevocationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(RevocationResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val encoderRevocationResponse: Encoder[RevocationResponse] =
    Encoder.instance[RevocationResponse] { a =>
      Json.obj(
        "resultCode" -> Json.fromString(a.getResultCode()),
        "resultMessage" -> Json.fromString(a.getResultMessage()),
        "action" -> Json.fromString(a.getAction().toString()),
        "responseContent" -> Json.fromString(a.getResponseContent())
      )
    }

  implicit val apiResponseDecoder: Decoder[ApiResponse] = Decoder.instance {
    h =>
      for {
        resultCode <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultMessage")
      } yield {
        var api = ApiResponse()
        api.setResultCode(resultCode)
        api.setResultMessage(resultMessage)
        api
      }

  }

  implicit val apiResponseEncoder: Encoder[ApiResponse] =
    Encoder.instance[ApiResponse] { resp =>
      Json.obj(
        "resultCode" -> Json.fromString(resp.getResultCode()),
        "resultMessage" -> Json.fromString(resp.getResultMessage())
      )
    }

  implicit val clientDecoder: Decoder[Client] = Decoder.instance { h =>
    for {
      clientId <- h.get[Long]("clientId")
      clientName <- h.get[String]("clientName")
    } yield {
      var client = Client()
      client.setClientId(clientId)
      client.setClientName(clientName)
      client
    }
  }

  implicit val clientEncoder: Encoder[Client] = Encoder.instance[Client] { c =>
    Json.obj(
      "clientId" -> Json.fromLong(c.getClientId()),
      "clientName" -> Json.fromString(c.getClientName())
    )
  }

  implicit val encoderTokenRequest: Encoder[TokenRequest] =
    Encoder.instance[TokenRequest] { a =>
      Json.obj(
        "parameters" -> Json.fromString(a.getParameters()),
        "clientId" -> Json.fromString(a.getClientId()),
        "clientSecret" -> Json.fromString(a.getClientSecret()),
        "clientCertificate" -> Json.fromString(a.getClientCertificate()),
        "clientCertificatePath" -> Json.arr(
          a.getClientCertificatePath().map(Json.fromString): _*
        ),
        "properties" -> Json.fromValues(
          a.getProperties()
            .map(prop =>
              Json.obj(prop.getKey() -> Json.fromString(prop.getValue()))
            )
        ),
        "dpop" -> Json.fromString(a.getDpop()),
        "htm" -> Json.fromString(a.getHtm()),
        "htu" -> Json.fromString(a.getHtu()),
        "jwtAtClaims" -> Json.fromString(a.getJwtAtClaims()),
        "accessToken" -> Json.fromString(a.getAccessToken()),
        "accessTokenDuration" -> Json.fromLong(a.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(a.getRefreshTokenDuration()),
        "dpopNonceRequired" -> Json.fromBoolean(a.isDpopNonceRequired()),
        "oauthClientAttestation" -> Json.fromString(
          a.getOauthClientAttestation()
        )
      )
    }

  implicit val decoderTokenResponse: Decoder[TokenResponse] = Decoder.instance {
    h =>
      for {
        resultCode <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultMessage")
        action <- h.get[String]("action")
        clientId <- h.get[String]("clientId")
        accessToken <- h.get[String]("accessToken")
        accessTokenExpiresAt <- h.get[Long]("accessTokenExpiresAt")
        accessTokenDuration <- h.get[Long]("accessTokenDuration")
        refreshToken <- h.get[String]("refreshToken")
        refreshTokenExpiresAt <- h.get[Long]("refreshTokenExpiresAt")
        refreshTokenDuration <- h.get[Long]("refreshTokenDuration")
        idToken <- h.get[String]("idToken")
        jwtAccessToken <- h.get[String]("jwtAccessToken")
        properties <- h.get[List[String]]("properties") // .map()
      } yield {
        var response = TokenResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(TokenResponse.Action.valueOf(action))
        response.setClientId(clientId.toLong)
        response.setAccessToken(accessToken)
        response.setAccessTokenExpiresAt(accessTokenExpiresAt)
        response.setAccessTokenDuration(accessTokenDuration)
        response.setRefreshToken(refreshToken)
        response.setRefreshTokenExpiresAt(refreshTokenExpiresAt)
        response.setRefreshTokenDuration(refreshTokenDuration)
        response.setIdToken(idToken)
        response.setJwtAccessToken(jwtAccessToken)
        // response.setProperties(properties)
        response
      }
  }

  implicit val encoderAuthorizationRequest: Encoder[AuthorizationRequest] =
    Encoder.instance[AuthorizationRequest] { a =>
      Json.obj(
        "parameters" -> Json.fromString(a.getParameters()),
        "context" -> Json.fromString(a.getContext())
      )
    }

  implicit val encoderIntrospectionRequest: Encoder[IntrospectionRequest] =
    Encoder.instance[IntrospectionRequest] { a =>
      Json.obj(
        "token" -> Json.fromString(a.getToken()),
        "scopes" -> Json.fromValues(a.getScopes().map(Json.fromString)),
        "subject" -> Json.fromString(a.getSubject()),
        "clientCertificate" -> Json.fromString(a.getClientCertificate()),
        "dpop" -> Json.fromString(a.getDpop()),
        "htm" -> Json.fromString(a.getHtm()),
        "htu" -> Json.fromString(a.getHtu())
      )
    }

  implicit val encoderIntrospectionResponse: Encoder[IntrospectionResponse] =
    Encoder.instance[IntrospectionResponse] { resp =>
      Json.obj(
        "resultCode" -> Json.fromString(resp.getResultCode()),
        "resultMessage" -> Json.fromString(resp.getResultMessage()),
        "action" -> Json.fromString(resp.getAction().toString()),
        "clientId" -> Json.fromLong(resp.getClientId()),
        "subject" -> Json.fromString(resp.getSubject()),
        "scopes" -> Json.fromValues(resp.getScopes().map(Json.fromString)),
        // "scopeDetails" -> Json.fromValues(resp.getScopeDetails().map(Json.fromString)),
        "existent" -> Json.fromBoolean(resp.isExistent()),
        "usable" -> Json.fromBoolean(resp.isUsable()),
        "sufficient" -> Json.fromBoolean(resp.isSufficient()),
        "refreshable" -> Json.fromBoolean(resp.isRefreshable()),
        "responseContent" -> Json.fromString(resp.getResponseContent()),
        "certificateThumbprint" -> Json.fromString(
          resp.getCertificateThumbprint()
        ),
        "grantId" -> Json.fromLong(resp.getGrantId().toLong),
        "consentedClaims" -> Json.fromValues(
          resp.getConsentedClaims().map(Json.fromString)
        ),
        "expiresAt" -> Json.fromLong(resp.getExpiresAt()),
        "acr" -> Json.fromString(resp.getAcr()),
        "authTime" -> Json.fromLong(resp.getAuthTime()),
        "cnonce" -> Json.fromString(resp.getCnonce()),
        "cnonceExpiresAt" -> Json.fromLong(resp.getCnonceExpiresAt()),
        "dpopNonce" -> Json.fromString(resp.getDpopNonce()),
        "responseSigningRequired" -> Json.fromBoolean(
          resp.isResponseSigningRequired()
        )
      )

    }

  implicit val decoderIntrospectionResponse: Decoder[IntrospectionResponse] =
    Decoder.instance { h =>
      for {
        resultCode <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultMessage")
        action <- h.get[String]("action")
        clientId <- h.get[Long]("clientId")
        subject <- h.get[String]("subject")
        scopes <- h.get[Array[String]]("scopes")
        scopeDetails <- h.get[Array[String]]("scopeDetails")
        existent <- h.get[Boolean]("existent")
        usable <- h.get[Boolean]("usable")
        sufficient <- h.get[Boolean]("sufficient")
        refreshable <- h.get[Boolean]("refreshable")
        responseContent <- h.get[String]("responseContent")
        certificateThumbprint <- h.get[String]("certificateThumbprint")
        grantId <- h.get[Long]("grantId")
        consentedClaims <- h.get[Array[String]]("consentedClaims")
        expiresAt <- h.get[Long]("expiresAt")
        acr <- h.get[String]("acr")
        authTime <- h.get[Long]("authTime")
        cnonce <- h.get[String]("cnonce")
        cnonceExpiresAt <- h.get[Long]("cnonceExpiresAt")
        dpopNonce <- h.get[String]("dpopNonce")
        responseSigningRequired <- h.get[Boolean]("responseSigningRequired")
      } yield {
        var response = IntrospectionResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(IntrospectionResponse.Action.valueOf(action))
        response.setClientId(clientId)
        response.setSubject(subject)
        // response.setScopes(scopes)
        response
      }
    }

  implicit val decoderAuthorizationResponse: Decoder[AuthorizationResponse] =
    Decoder.instance(h => {
      for {
        resultCode <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultMessage")
        action <- h.get[String]("action")
        maxAge <- h.get[Int]("maxAge")
        scopes <- h.get[Array[String]]("scopes")
        claims <- h.get[Array[String]]("claims")
        claimsAtUserInfo <- h.get[Array[String]]("claimsAtUserInfo")
        acrEssential <- h.get[Boolean]("acrEssential")
        acrs <- h.get[Array[String]]("acrs")
        subject <- h.get[String]("subject")
        idTokenClaims <- h.get[String]("idTokenClaims")
        userInfoClaims <- h.get[String]("userInfoClaims")
      } yield {
        var response = AuthorizationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(AuthorizationResponse.Action.valueOf(action))
        response.setMaxAge(maxAge)
        // response.setScopes(scopes)
        response
      }
    })

  implicit val encoderAuthorizationResponse: Encoder[AuthorizationResponse] =
    Encoder.instance[AuthorizationResponse] { a =>
      Json.obj(
        "resultCode" -> Json.fromString(a.getResultCode()),
        "resultMessage" -> Json.fromString(a.getResultMessage()),
        "action" -> Json.fromString(a.getAction().toString()),
        "maxAge" -> Json.fromInt(a.getMaxAge()),
        /// "scopes" -> Json.arr(a.getScopes().map(Json.fromString): _*),
        "claims" -> Json.arr(a.getClaims().map(Json.fromString): _*),
        "claimsAtUserInfo" -> Json.arr(
          a.getClaimsAtUserInfo().map(Json.fromString): _*
        ),
        "acrEssential" -> Json.fromBoolean(a.isAcrEssential()),
        "acrs" -> Json.arr(a.getAcrs().map(Json.fromString): _*),
        "subject" -> Json.fromString(a.getSubject()),
        "idTokenClaims" -> Json.fromString(a.getIdTokenClaims()),
        "userInfoClaims" -> Json.fromString(a.getUserInfoClaims())
      )
    }

  implicit val encoderAuthzDetailsElement: Encoder[AuthzDetailsElement] =
    Encoder.instance[AuthzDetailsElement] { a =>
      Json.obj(
        "type" -> Json.fromString(a.getType()),
        "locations" -> Json.arr(a.getLocations().map(Json.fromString): _*),
        "actions" -> Json.arr(a.getActions().map(Json.fromString): _*),
        "dataTypes" -> Json.arr(a.getDataTypes().map(Json.fromString): _*),
        "identifier" -> Json.fromString(a.getIdentifier()),
        "privileges" -> Json.arr(a.getPrivileges().map(Json.fromString): _*),
        "otherFields" -> Json.fromString(a.getOtherFields())
      )
    }

  implicit val encoderAuthorizationIssueRequest
      : Encoder[AuthorizationIssueRequest] =
    Encoder.instance[AuthorizationIssueRequest] { a =>
      Json.obj(
        "ticket" -> Json.fromString(a.getTicket()),
        "subject" -> Json.fromString(a.getSubject()),
        "sub" -> Json.fromString(a.getSub()),
        "authTime" -> Json.fromLong(a.getAuthTime()),
        "acr" -> Json.fromString(a.getAcr()),
        "claims" -> Json.fromString(a.getClaims()),
        "properties" -> Json.fromValues(
          a.getProperties()
            .map(prop =>
              Json.obj(prop.getKey() -> Json.fromString(prop.getValue()))
            )
        )
      )
    }

  implicit val decoderAuthorizationIssueResponse
      : Decoder[AuthorizationIssueResponse] = Decoder.instance(h => {
    for {
      resultCode <- h.get[String]("resultCode")
      resultMessage <- h.get[String]("resultMessage")
      action <- h.get[String]("action")
      responseContent <- h.get[String]("responseContent")
      accessToken <- h.get[String]("accessToken")
      accessTokenExpiresAt <- h.get[Long]("accessTokenExpiresAt")
      accessTokenDuration <- h.get[Long]("accessTokenDuration")
      idToken <- h.get[String]("idToken")
      authorizationCode <- h.get[String]("authorizationCode")
      jwtAccessToken <- h.get[String]("jwtAccessToken")

      // ticketInfo <- h.get[String]("ticket")

    } yield {
      var response = AuthorizationIssueResponse()
      response.setResultCode(resultCode)
      response.setResultMessage(resultMessage)
      response.setAction(AuthorizationIssueResponse.Action.valueOf(action))
      response.setResponseContent(responseContent)
      response.setAccessToken(accessToken)

      response.setAccessTokenExpiresAt(accessTokenExpiresAt)
      response.setAccessTokenDuration(accessTokenDuration)
      response.setIdToken(idToken)
      response.setAuthorizationCode(authorizationCode)
      response.setJwtAccessToken(jwtAccessToken)
      response
    }
  })

  implicit val encoderAuthorizationIssueResponse
      : Encoder[AuthorizationIssueResponse] =
    Encoder.instance[AuthorizationIssueResponse] { a =>
      Json.obj(
        "resultCode" -> Json.fromString(a.getResultCode()),
        "resultMessage" -> Json.fromString(a.getResultMessage()),
        "action" -> Json.fromString(a.getAction().toString()),
        "responseContent" -> Json.fromString(a.getResponseContent()),
        "accessToken" -> Json.fromString(a.getAccessToken()),
        "accessTokenExpiresAt" -> Json.fromLong(a.getAccessTokenExpiresAt()),
        "accessTokenDuration" -> Json.fromLong(a.getAccessTokenDuration()),
        "idToken" -> Json.fromString(a.getIdToken()),
        "authorizationCode" -> Json.fromString(a.getAuthorizationCode()),
        "jwtAccessToken" -> Json.fromString(a.getJwtAccessToken())
      )
    }

  implicit val encoderAuthorizationFailRequest
      : Encoder[AuthorizationFailRequest] =
    Encoder.instance[AuthorizationFailRequest] { a =>
      Json.obj(
        "ticket" -> Json.fromString(a.getTicket()),
        "reason" -> Json.fromString(a.getReason().toString()),
        "description" -> Json.fromString(a.getDescription())
      )
    }

  implicit val decoderAuthorizationFailResponse
      : Decoder[AuthorizationFailResponse] = Decoder.instance { h =>
    for {
      resultCode <- h.get[String]("resultCode")
      resultMessage <- h.get[String]("resultMessage")
      action <- h.get[String]("action")
      responseContent <- h.get[String]("responseContent")
    } yield {
      var response = AuthorizationFailResponse()
      response.setResultCode(resultCode)
      response.setResultMessage(resultMessage)
      response.setAction(AuthorizationFailResponse.Action.valueOf(action))
      response.setResponseContent(responseContent)
      response

    }
  }

  implicit val encoderAuthorizationFailResponse
      : Encoder[AuthorizationFailResponse] =
    Encoder.instance[AuthorizationFailResponse] { a =>
      Json.obj(
        "resultCode" -> Json.fromString(a.getResultCode()),
        "resultMessage" -> Json.fromString(a.getResultMessage()),
        "action" -> Json.fromString(a.getAction().toString()),
        "responseContent" -> Json.fromString(a.getResponseContent())
      )
    }
  implicit def jsonEntityDecoder[F[_]: Async, A](using
      Decoder[A]
  ): EntityDecoder[F, A] = {
    EntityDecoder.decodeBy[F, A](MediaType.application.json) { msg =>
      DecodeResult[F, A](
        msg.as[String].flatMap { str =>
          Async[F].delay {
            jawn.decodeAccumulating[A](str).leftMap(_.head).toEither match {
              case Right(report) =>
                Right(report)
              case Left(err) =>
                Left(MalformedMessageBodyFailure(err.getMessage, cause = None))
            }
          }
        }
      )
    }
  }

  implicit def clientApiResonseDecoder[F[_]: Concurrent]
      : EntityDecoder[F, Either[ApiResponse, Client]] =
    EntityDecoder.decodeBy[F, Either[ApiResponse, Client]](
      MediaType.application.json
    ) { msg =>
      clientEntityDecoder
        .decode(msg, strict = false)
        .map(_.asRight[ApiResponse])
        .handleErrorWith(_ =>
          apiResponseEntityDecoder
            .decode(msg, strict = false)
            .map(_.asLeft[Client])
        )
    }

  // implicit def clientApiResonseDecoder2[F[_]: Concurrent]
  //         : EntityDecoder[F, Client | ApiResponse] =
  //       EntityDecoder.decodeBy(MediaType.application.json) { msg =>
  //         EntityDecoder.collectBinary(msg).map { bytes =>
  //           val str = new String(bytes.toArray, "UTF-8")
  //           parser.decode[Client](str) match {
  //             case Right(client) => client
  //             case Left(apiResponse) =>
  //               var res = ApiResponse()
  //               res.setResultMessage(apiResponse.getMessage())
  //               res
  //           }
  //         }
  //       }

  implicit def clientApiResonseDecoder3[F[_]: Concurrent]
      : EntityDecoder[F, Client | ApiResponse] =
    EntityDecoder.decodeBy[F, Client | ApiResponse](
      MediaType.application.json
    ) { msg =>
      clientEntityDecoder
        .decode(msg, strict = false)
        .map(_.asInstanceOf[Client | ApiResponse])
        .handleErrorWith(_ =>
          apiResponseEntityDecoder
            .decode(msg, strict = false)
            .map(_.asInstanceOf[Client | ApiResponse])
        )
    }

  implicit def tokenRequestEnittyEncoder[F[_]]: EntityEncoder[F, TokenRequest] =
    jsonEncoderOf[F, TokenRequest]

  implicit def authorizationRequestEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationRequest] =
    jsonEncoderOf[F, AuthorizationRequest]

  implicit def authorizationIssueRequestEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationIssueRequest] =
    jsonEncoderOf[F, AuthorizationIssueRequest]

  implicit def authorizationFailRequestEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationFailRequest] =
    jsonEncoderOf[F, AuthorizationFailRequest]

  implicit def introspectionRequestEntityEncoder[F[_]]
      : EntityEncoder[F, IntrospectionRequest] =
    jsonEncoderOf[F, IntrospectionRequest]

  implicit def introspectionResponseEntityEncoder[F[_]]
      : EntityEncoder[F, IntrospectionResponse] =
    jsonEncoderOf[F, IntrospectionResponse]

  implicit def revocationRequestEntityEncoder[F[_]]
      : EntityEncoder[F, RevocationRequest] =
    jsonEncoderOf[F, RevocationRequest]

  implicit def revocationResponseEntityEncoder[F[_]]
      : EntityEncoder[F, RevocationResponse] =
    jsonEncoderOf[F, RevocationResponse]

  implicit def authorizationResponseEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationResponse] =
    jsonEncoderOf[F, AuthorizationResponse]

  implicit def authorizationIssueResponseEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationIssueResponse] =
    jsonEncoderOf[F, AuthorizationIssueResponse]

  implicit def authorizationFailResponseEntityEncoder[F[_]]
      : EntityEncoder[F, AuthorizationFailResponse] =
    jsonEncoderOf[F, AuthorizationFailResponse]

  implicit def apiResponseEntityEncoder[F[_]]: EntityEncoder[F, ApiResponse] =
    jsonEncoderOf[F, ApiResponse]

  implicit def clientEntityEncoder[F[_]]: EntityEncoder[F, Client] =
    jsonEncoderOf[F, Client]

  implicit def clientEntityDecoder[F[_]: Concurrent]: EntityDecoder[F, Client] =
    jsonOf[F, Client]

  implicit def apiResponseEntityDecoder[F[_]: Concurrent]
      : EntityDecoder[F, ApiResponse] = jsonOf[F, ApiResponse]

}
