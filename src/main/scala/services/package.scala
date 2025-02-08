import java.net.URI

import cats.effect.kernel.Async
import cats.effect.Concurrent
import cats.syntax.all.*
import cats.syntax.show.*
import cats.MonadThrow
import cats.Show

import com.authlete.common.dto.*
import com.authlete.common.dto.Property
import com.authlete.common.types.*
//   import org.http4s.circe.CirceEntityDecoder.circeEntityDecoder
import io.circe.generic.auto.deriveDecoder
import io.circe.jawn
import io.circe.parser
import io.circe.Decoder
import io.circe.Encoder
import io.circe.Json
import org.http4s.circe.*
import org.http4s.circe.middleware.JsonDebugErrorHandler
//import org.http4s.EntityDecoder.*
import org.http4s.circe.CirceEntityCodec.circeEntityDecoder
import org.http4s.DecodeResult
import org.http4s.EntityDecoder
import org.http4s.EntityEncoder
import org.http4s.InvalidMessageBodyFailure
import org.http4s.MalformedMessageBodyFailure
import org.http4s.MediaType
import utils.*

package object services {

  implicit val showApiResponse: Show[ApiResponse] =
    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage
    )

  implicit val showClient: Show[Client] =
    showHelper(
      "ClientId"   -> _.getClientId.show,
      "ClientName" -> _.getClientName
    )

  implicit val showAuthorizationRequest: Show[AuthorizationRequest] =
    // `parameters` can contain sensitives like pkce challenge
    showHelper()

  implicit val showAuthorizationResponse: Show[AuthorizationResponse] = {
    implicit val showAction: Show[AuthorizationResponse.Action] = fromToString
    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      x => "Action" -> x.getAction.show
    )
  }

  implicit val showAuthorizationIssueRequest: Show[AuthorizationIssueRequest] =
    showHelper()

  implicit val showAuthorizationIssueResponse: Show[AuthorizationIssueResponse] = {

    implicit val showAction: Show[AuthorizationIssueResponse.Action] =
      Show.show((action: AuthorizationIssueResponse.Action) => action.toString)

    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action"        -> _.getAction.show
    )
  }

  implicit val showAuthorizationFailResponse: Show[AuthorizationFailResponse] = {
    implicit val showAction: Show[AuthorizationFailResponse.Action] =
      Show.show((action: AuthorizationFailResponse.Action) => action.toString)
    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action"        -> _.getAction.show
    )
  }

  implicit val showTokenRequest: Show[TokenRequest] = {
    showHelper(
      "ClientId" -> _.getClientId
    )
  }

  implicit val showTokenResponse: Show[TokenResponse] = {
    implicit val showAction: Show[TokenResponse.Action] =
      Show.show((action: TokenResponse.Action) => action.toString)

    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action"        -> _.getAction.show,
      "ClientId"      -> _.getClientId.show
    )
  }

  implicit val showIntrospectionRequest: Show[IntrospectionRequest] =
    showHelper()

  implicit val showIntrospectionResponse: Show[IntrospectionResponse] = {
    implicit val showAction: Show[IntrospectionResponse.Action] = fromToString
    showHelper(
      "ResultCode"    -> _.getResultCode,
      "ResultMessage" -> _.getResultMessage,
      "Action"        -> _.getAction.show,
      "ClientId"      -> _.getClientId.show
    )
  }

  implicit val showRevocationRequest: Show[RevocationRequest] =
    showHelper("ClientId" -> _.getClientId)

  def fromToString[A]: Show[A] = _.toString

  implicit val showRevocationResponse: Show[RevocationResponse] = {
    implicit val showAction: Show[RevocationResponse.Action] = fromToString
    showHelper(
      "ResultMessage" -> _.getResultMessage,
      "Action"        -> _.getAction.show
    )
  }

  implicit val showAuthorizationFailRequest: Show[AuthorizationFailRequest] = {
    implicit val showReason: Show[AuthorizationFailRequest.Reason] =
      fromToString
    showHelper(
      "Ticket"      -> _.getTicket,
      "Reason"      -> _.getReason.show,
      "description" -> _.getDescription
    )
  }

  implicit val authzDetailsElementEncoder: Encoder[AuthzDetailsElement] =
    Encoder.instance[AuthzDetailsElement] { a =>
      Json.obj(
        "type"        -> Json.fromString(a.getType()),
        "locations"   -> Json.arr(a.getLocations().map(Json.fromString): _*),
        "actions"     -> Json.arr(a.getActions().map(Json.fromString): _*),
        "dataTypes"   -> Json.arr(a.getDataTypes().map(Json.fromString): _*),
        "identifier"  -> Json.fromString(a.getIdentifier()),
        "privileges"  -> Json.arr(a.getPrivileges().map(Json.fromString): _*),
        "otherFields" -> Json.fromString(a.getOtherFields())
      )
    }

  implicit val authzDetailsEncoder: Encoder[AuthzDetails] =
    Encoder.instance[AuthzDetails] { a =>
      Json.obj(
        "elements" -> Json.fromValues(
          a.getElements().map(authzDetailsElementEncoder.apply)
        )
      )
    }

  implicit val authzDetailsElementDecoder: Decoder[AuthzDetailsElement] =
    Decoder.instance { h =>
      for {
        `type`      <- h.get[Option[String]]("type").map(_.orNull)
        locations   <- h.get[Array[String]]("locations")
        actions     <- h.get[Array[String]]("actions")
        dataTypes   <- h.get[Array[String]]("dataTypes")
        identifier  <- h.get[Option[String]]("identifier").map(_.orNull)
        privileges  <- h.get[Array[String]]("privileges")
        otherFields <- h.get[Option[String]]("otherFields").map(_.orNull)
      } yield {
        var element = AuthzDetailsElement()
        element.setType(`type`)
        element.setLocations(locations)
        element.setActions(actions)
        element.setDataTypes(dataTypes)
        element.setIdentifier(identifier)
        element.setPrivileges(privileges)
        element.setOtherFields(otherFields)
        element
      }
    }

  implicit val authzDetailsDecoder: Decoder[AuthzDetails] = Decoder.instance { h =>
    for {
      elements <- h.get[Array[AuthzDetailsElement]]("elements")
    } yield {
      var details = AuthzDetails()
      details.setElements(elements)
      details
    }
  }

  implicit val pairEncoder: Encoder[Pair] = Encoder.instance[Pair] { p =>
    Json.obj(
      "key"   -> Json.fromString(p.getKey()),
      "value" -> Json.fromString(p.getValue())
    )
  }

  implicit val pairDecoder: Decoder[Pair] = Decoder.instance[Pair] { h =>
    for {
      key   <- h.get[Option[String]]("key").map(_.orNull)
      value <- h.get[Option[String]]("value").map(_.orNull)
    } yield {
      var pair = Pair()
      pair.setKey(key)
      pair.setValue(value)
      pair
    }
  }

  implicit val accessTokenEncoder: Encoder[AccessToken] =
    Encoder.instance[AccessToken] { a =>
      Json.obj(
        "accessTokenHash"       -> Json.fromString(a.getAccessTokenHash()),
        "refreshTokenHash"      -> Json.fromString(a.getRefreshTokenHash()),
        "clientId"              -> Json.fromLong(a.getClientId()),
        "subject"               -> Json.fromString(a.getSubject()),
        "grantType"             -> Json.fromString(a.getGrantType().toString()),
        "scopes"                -> Json.fromValues(a.getScopes().map(Json.fromString)),
        "accessTokenExpiresAt"  -> Json.fromLong(a.getAccessTokenExpiresAt()),
        "refreshTokenExpiresAt" -> Json.fromLong(a.getRefreshTokenExpiresAt()),
        "createdAt"             -> Json.fromLong(a.getCreatedAt()),
        "lastRefreshedAt"       -> Json.fromLong(a.getLastRefreshedAt()),
        "properties" -> Json.arr(
          a.getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue())))* // _*
        ),
        "refreshTokenScopes" -> Json.fromValues(
          a.getRefreshTokenScopes().map(Json.fromString)
        )
      )
    }

  implicit val accessTokenDecoder: Decoder[AccessToken] = Decoder.instance { h =>
    for {
      accessTokenHash  <- h.get[Option[String]]("accessTokenHash").map(_.orNull)
      refreshTokenHash <- h.get[Option[String]]("refreshTokenHash").map(_.orNull)
      clientId         <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))

      subject <- h.get[Option[String]]("subject").map(_.orNull)

      grantType <- h.get[Option[String]]("grantType").map(_.orNull)

      scopes <- h.get[Option[Array[String]]]("scopes").map(_.getOrElse(Array.empty[String]))

      accessTokenExpiresAt <- h.get[Option[Long]]("accessTokenExpiresAt").map(_.getOrElse(0L))

      refreshTokenExpiresAt <- h.get[Option[Long]]("refreshTokenExpiresAt").map(_.getOrElse(0L))

      createdAt <- h.get[Option[Long]]("createdAt").map(_.getOrElse(0L))

      lastRefreshedAt <- h.get[Option[Long]]("lastRefreshedAt").map(_.getOrElse(0L))

      // properties <- h.get[Array[Property]]("properties")

      refreshTokenScopes <-
        h.get[Option[Array[String]]]("refreshTokenScopes").map(_.getOrElse(Array.empty[String]))

    } yield {
      var token = AccessToken()
      token.setAccessTokenHash(accessTokenHash)
      token.setRefreshTokenHash(refreshTokenHash)
      token.setClientId(clientId)
      token.setSubject(subject)
      token.setGrantType(GrantType.valueOf(grantType))
      token.setScopes(scopes)
      token.setAccessTokenExpiresAt(accessTokenExpiresAt)
      token.setRefreshTokenExpiresAt(refreshTokenExpiresAt)
      token.setCreatedAt(createdAt)
      token.setLastRefreshedAt(lastRefreshedAt)
      // token.setProperties(properties)
      token.setRefreshTokenScopes(refreshTokenScopes)
      token
    }
  }

// implicit val clientEncoder: Encoder[Client] = Encoder.instance[Client] { c =>
//    Json.obj(
//      "clientId" -> Json.fromLong(c.getClientId()),
//      "clientName" -> Json.fromString(c.getClientName())
//    )
//  }

  implicit val clientEncoder: Encoder[Client] = Encoder.instance[Client] { c =>
    Json.obj(
      "number"               -> Json.fromInt(c.getNumber()),
      "serviceNumber"        -> Json.fromInt(c.getServiceNumber()),
      "developer"            -> Json.fromString(c.getDeveloper()),
      "clientId"             -> Json.fromLong(c.getClientId()),
      "clientIdAlias"        -> Json.fromString(c.getClientIdAlias()),
      "clientIdAliasEnabled" -> Json.fromBoolean(c.isClientIdAliasEnabled()),
      "clientSecret"         -> Json.fromString(c.getClientSecret()),
      "clientType"           -> Json.fromString(c.getClientType().toString()),
      "redirectUris" -> Json.fromValues(
        c.getRedirectUris().map(Json.fromString)
      ),
      "responseTypes" -> Json.fromValues(
        c.getResponseTypes().map(resType => Json.fromString(resType.toString()))
      ),
      "grantTypes" -> Json.fromValues(
        c.getGrantTypes().map(grantType => Json.fromString(grantType.toString()))
      ),
      "applicationType" -> Json.fromString(c.getApplicationType().toString()),
      "contacts"        -> Json.fromValues(c.getContacts().map(Json.fromString)),
      "clientName"      -> Json.fromString(c.getClientName()),
      "clientNames" -> Json.fromValues(
        c.getClientNames().map(tag => Json.obj(tag.getTag() -> Json.fromString(tag.getValue())))
      ),
      "logoUri" -> Json.fromString(c.getLogoUri().toString()),
      "logoUris" -> Json.fromValues(
        c.getLogoUris().map(uri => Json.obj(uri.getTag() -> Json.fromString(uri.getValue())))
      ),
      "clientUri" -> Json.fromString(c.getClientUri().toString()),
      "clientUris" -> Json.fromValues(
        c.getClientUris().map(uri => Json.obj(uri.getTag() -> Json.fromString(uri.getValue())))
      ),
      "policyUri" -> Json.fromString(c.getPolicyUri().toString()),
      "policyUris" -> Json.fromValues(
        c.getPolicyUris().map(uri => Json.obj(uri.getTag() -> Json.fromString(uri.getValue())))
      ),
      "tosUri" -> Json.fromString(c.getTosUri().toString()),
      "tosUris" -> Json.fromValues(
        c.getTosUris().map(uri => Json.obj(uri.getTag() -> Json.fromString(uri.getValue())))
      ),
      "jwksUri" -> Json.fromString(c.getJwksUri().toString()),
      "jwks"    -> Json.fromString(c.getJwks()),
      "derivedSectorIdentifier" -> Json.fromString(
        c.getDerivedSectorIdentifier()
      ),
      "sectorIdentifierUri" -> Json.fromString(
        c.getSectorIdentifierUri().toString()
      ),
      "subjectType"    -> Json.fromString(c.getSubjectType().toString()),
      "idTokenSignAlg" -> Json.fromString(c.getIdTokenSignAlg().toString()),
      "idTokenEncryptionAlg" -> Json.fromString(
        c.getIdTokenEncryptionAlg().toString()
      ),
      "idTokenEncryptionEnc" -> Json.fromString(
        c.getIdTokenEncryptionEnc().getName()
      ),
      "userInfoSignAlg" -> Json.fromString(c.getUserInfoSignAlg().toString()),
      "userInfoEncryptionAlg" -> Json.fromString(
        c.getUserInfoEncryptionAlg().toString()
      ),
      "userInfoEncryptionEnc" -> Json.fromString(
        c.getUserInfoEncryptionEnc().getName()
      ),
      "requestSignAlg" -> Json.fromString(c.getRequestSignAlg().toString()),
      "requestEncryptionAlg" -> Json.fromString(
        c.getRequestEncryptionAlg().toString()
      ),
      "requestEncryptionEnc" -> Json.fromString(
        c.getRequestEncryptionEnc().getName()
      ),
      "tokenAuthMethod"  -> Json.fromString(c.getTokenAuthMethod().toString()),
      "tokenAuthSignAlg" -> Json.fromString(c.getTokenAuthSignAlg().toString()),
      "defaultMaxAge"    -> Json.fromInt(c.getDefaultMaxAge()),
      "defaultAcrs"      -> Json.fromValues(c.getDefaultAcrs().map(Json.fromString)),
      "authTimeRequired" -> Json.fromBoolean(c.isAuthTimeRequired()),
      "loginUri"         -> Json.fromString(c.getLoginUri().toString()),
      "requestUris"      -> Json.fromValues(c.getRequestUris().map(Json.fromString)),
      "description"      -> Json.fromString(c.getDescription()),
      "descriptions" -> Json.fromValues(
        c.getDescriptions().map(desc => Json.obj(desc.getTag() -> Json.fromString(desc.getValue())))
      ),
      "createdAt"  -> Json.fromLong(c.getCreatedAt()),
      "modifiedAt" -> Json.fromLong(c.getModifiedAt()),
      "extension"  -> Json.fromString(c.getExtension().toString()),
      "tlsClientAuthSubjectDn" -> Json.fromString(
        c.getTlsClientAuthSubjectDn()
      ),
      "tlsClientAuthSanDns" -> Json.fromString(c.getTlsClientAuthSanDns()),
      "tlsClientAuthSanUri" -> Json.fromString(
        c.getTlsClientAuthSanUri().toString()
      ),
      "tlsClientAuthSanIp"    -> Json.fromString(c.getTlsClientAuthSanIp()),
      "tlsClientAuthSanEmail" -> Json.fromString(c.getTlsClientAuthSanEmail()),
      "tlsClientCertificateBoundAccessTokens" -> Json.fromBoolean(
        c.isTlsClientCertificateBoundAccessTokens()
      ),
      "selfSignedCertificateKeyId" -> Json.fromString(
        c.getSelfSignedCertificateKeyId()
      ),
      "softwareId"      -> Json.fromString(c.getSoftwareId()),
      "softwareVersion" -> Json.fromString(c.getSoftwareVersion()),
      "authorizationSignAlg" -> Json.fromString(
        c.getAuthorizationSignAlg().toString()
      ),
      "authorizationEncryptionAlg" -> Json.fromString(
        c.getAuthorizationEncryptionAlg().toString()
      ),
      "authorizationEncryptionEnc" -> Json.fromString(
        c.getAuthorizationEncryptionEnc().getName()
      ),
      "bcDeliveryMode" -> Json.fromString(c.getBcDeliveryMode().toString()),
      "bcNotificationEndpoint" -> Json.fromString(
        c.getBcNotificationEndpoint().toString()
      ),
      "attributes"     -> Json.fromValues(c.getAttributes().map(pairEncoder.apply)),
      "customMetadata" -> Json.fromString(c.getCustomMetadata()),
      "frontChannelRequestObjectEncryptionRequired" -> Json.fromBoolean(
        c.isFrontChannelRequestObjectEncryptionRequired()
      ),
      "requestObjectEncryptionAlgMatchRequired" -> Json.fromBoolean(
        c.isRequestObjectEncryptionAlgMatchRequired()
      ),
      "requestObjectEncryptionEncMatchRequired" -> Json.fromBoolean(
        c.isRequestObjectEncryptionEncMatchRequired()
      ),
      "digestAlgorithm" -> Json.fromString(c.getDigestAlgorithm()),
      "singleAccessTokenPerSubject" -> Json.fromBoolean(
        c.isSingleAccessTokenPerSubject()
      ),
      "pkceRequired"         -> Json.fromBoolean(c.isPkceRequired()),
      "pkceS256Required"     -> Json.fromBoolean(c.isPkceS256Required()),
      "rsSignedRequestKeyId" -> Json.fromString(c.getRsSignedRequestKeyId()),
      // "rsRequestSigned" -> Json.fromBoolean(c.isRsRequestSigned()),
      "dpopRequired" -> Json.fromBoolean(c.isDpopRequired()),
      "locked"       -> Json.fromBoolean(c.isLocked()),
      "fapiModes" -> Json.fromValues(
        c.getFapiModes().map(mode => Json.fromString(mode.toString()))
      ),
      "responseModes" -> Json.fromValues(
        c.getResponseModes().map(mode => Json.fromString(mode.toString()))
      ),
      "mtlsEndpointAliasesUsed" -> Json.fromBoolean(
        c.isMtlsEndpointAliasesUsed()
      ),
      "entityId"            -> Json.fromString(c.getEntityId().toString()),
      "trustAnchorId"       -> Json.fromString(c.getTrustAnchorId().toString()),
      "trustChain"          -> Json.fromValues(c.getTrustChain().map(Json.fromString)),
      "trustChainExpiresAt" -> Json.fromLong(c.getTrustChainExpiresAt()),
      "trustChainUpdatedAt" -> Json.fromLong(c.getTrustChainUpdatedAt()),
      "organizationName"    -> Json.fromString(c.getOrganizationName()),
      "signedJwksUri"       -> Json.fromString(c.getSignedJwksUri().toString()),
      "clientRegistrationTypes" -> Json.fromValues(
        c.getClientRegistrationTypes().map(regType => Json.fromString(regType.toString()))
      ),
      "automaticallyRegistered" -> Json.fromBoolean(
        c.isAutomaticallyRegistered()
      ),
      "explicitlyRegistered" -> Json.fromBoolean(c.isExplicitlyRegistered()),
      "credentialOfferEndpoint" -> Json.fromString(
        c.getCredentialOfferEndpoint().toString()
      ),
      "credentialResponseEncryptionRequired" -> Json.fromBoolean(
        c.isCredentialResponseEncryptionRequired()
      )
    )
  }

  implicit val clientDecoder: Decoder[Client] = Decoder.instance { h =>
    for {
      clientId   <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
      clientName <- h.get[Option[String]]("clientName").map(_.orNull)
    } yield {
      var client = Client()
      client.setClientId(clientId)
      client.setClientName(clientName)
      client
    }
  }

  implicit val scopeEncoder: Encoder[Scope] = Encoder.instance[Scope] { s =>
    Json.obj(
      "name"        -> Json.fromString(s.getName()),
      "description" -> Json.fromString(s.getDescription())
    )
  }

  implicit val scopeDecoder: Decoder[Scope] = Decoder.instance[Scope] { h =>
    for {
      name        <- h.get[Option[String]]("name").map(_.orNull)
      description <- h.get[Option[String]]("description").map(_.orNull)
    } yield {
      var scope = Scope()
      scope.setName(name)
      scope.setDescription(description)
      scope
    }
  }

  implicit val grantScopeDecoder: Decoder[GrantScope] =
    Decoder.instance[GrantScope] { h =>
      for {
        scope    <- h.get[Option[String]]("scope").map(_.orNull)
        resource <- h.get[Array[String]]("resource")
      } yield {
        var grantScope = GrantScope()
        grantScope.setScope(scope)
        grantScope.setResource(resource)
        grantScope
      }
    }

  implicit val grantDecoder: Decoder[Grant] = Decoder.instance[Grant] { h =>
    for {
      scopes               <- h.get[Array[GrantScope]]("scopes")
      claims               <- h.get[Array[String]]("claims")
      authorizationDetails <- h.get[AuthzDetails]("authorizationDetails")
    } yield {
      var grant = Grant()
      grant.setScopes(scopes)
      grant.setClaims(claims)
      grant.setAuthorizationDetails(authorizationDetails)
      grant
    }
  }

  implicit val tokenBatchStatusDecoder: Decoder[TokenBatchStatus] =
    Decoder.instance[TokenBatchStatus] { h =>
      for {
        batchKind        <- h.get[Option[String]]("batchKind").map(_.orNull)
        requestId        <- h.get[Option[String]]("requestId").map(_.orNull)
        result           <- h.get[Option[String]]("result").map(_.orNull)
        tokenCount       <- h.get[Option[Long]]("tokenCount").map(_.getOrElse(0L))
        errorCode        <- h.get[Option[String]]("errorCode").map(_.orNull)
        errorDescription <- h.get[Option[String]]("errorDescription").map(_.orNull)
        createdAt        <- h.get[Option[Long]]("createdAt").map(_.getOrElse(0L))
        modifiedAt       <- h.get[Option[Long]]("modifiedAt").map(_.getOrElse(0L))

      } yield {
        var tokenBatchStatus = TokenBatchStatus()
        tokenBatchStatus.setBatchKind(
          TokenBatchStatus.BatchKind.valueOf(batchKind)
        )
        tokenBatchStatus.setRequestId(requestId)
        tokenBatchStatus.setResult(TokenBatchStatus.Result.valueOf(result))
        tokenBatchStatus.setTokenCount(tokenCount)
        tokenBatchStatus.setErrorCode(errorCode)
        tokenBatchStatus.setErrorDescription(errorDescription)
        tokenBatchStatus.setCreatedAt(createdAt)
        tokenBatchStatus.setModifiedAt(modifiedAt)
        tokenBatchStatus
      }
    }

  implicit val hskDecoder: Decoder[Hsk] = Decoder.instance[Hsk] { h =>
    for {
      kty       <- h.get[Option[String]]("kty").map(_.orNull)
      use       <- h.get[Option[String]]("use").map(_.orNull)
      alg       <- h.get[Option[String]]("alg").map(_.orNull)
      kid       <- h.get[Option[String]]("kid").map(_.orNull)
      hsmName   <- h.get[Option[String]]("hsmName").map(_.orNull)
      handle    <- h.get[Option[String]]("handle").map(_.orNull)
      publicKey <- h.get[Option[String]]("publicKey").map(_.orNull)
    } yield {
      var hsk = Hsk()
      hsk.setKty(kty)
      hsk.setUse(use)
      hsk.setAlg(alg)
      hsk.setKid(kid)
      hsk.setHsmName(hsmName)
      hsk.setHandle(handle)
      hsk.setPublicKey(publicKey)
      hsk
    }
  }

  implicit val credentialOfferInfoDecoder: Decoder[CredentialOfferInfo] =
    Decoder.instance[CredentialOfferInfo] { h =>
      for {
        identifier       <- h.get[Option[String]]("identifier").map(_.orNull)
        credentialOffer  <- h.get[Option[String]]("credentialOffer").map(_.orNull)
        credentialIssuer <- h.get[URI]("credentialIssuer")
        credentialConfigurationIds <- h.get[Array[String]](
                                        "credentialConfigurationIds"
                                      )
        authorizationCodeGrantIncluded <- h.get[Option[Boolean]](
                                              "authorizationCodeGrantIncluded"
                                            )
                                            .map(_.getOrElse(false))
        issuerStateIncluded <- h.get[Option[Boolean]]("issuerStateIncluded").map(_.getOrElse(false))
        issuerState         <- h.get[Option[String]]("issuerState").map(_.orNull)
        preAuthorizedCodeGrantIncluded <- h.get[Option[Boolean]](
                                              "preAuthorizedCodeGrantIncluded"
                                            )
                                            .map(_.getOrElse(false))
        preAuthorizedCode <- h.get[Option[String]]("preAuthorizedCode").map(_.orNull)
        subject           <- h.get[Option[String]]("subject").map(_.orNull)
        expiresAt         <- h.get[Option[Long]]("expiresAt").map(_.getOrElse(0L))
        context           <- h.get[Option[String]]("context").map(_.orNull)
        // properties <- h.get[Array[Property]]("properties")
        jwtAtClaims       <- h.get[Option[String]]("jwtAtClaims").map(_.orNull)
        authTime          <- h.get[Option[Long]]("authTime").map(_.getOrElse(0L))
        acr               <- h.get[Option[String]]("acr").map(_.orNull)
        txCode            <- h.get[Option[String]]("txCode").map(_.orNull)
        txCodeInputMode   <- h.get[Option[String]]("txCodeInputMode").map(_.orNull)
        txCodeDescription <- h.get[Option[String]]("txCodeDescription").map(_.orNull)
      } yield {
        var credentialOfferInfo = CredentialOfferInfo()
        credentialOfferInfo.setIdentifier(identifier)
        credentialOfferInfo.setCredentialOffer(credentialOffer)
        credentialOfferInfo.setCredentialIssuer(credentialIssuer)
        credentialOfferInfo.setCredentialConfigurationIds(
          credentialConfigurationIds
        )
        credentialOfferInfo.setAuthorizationCodeGrantIncluded(
          authorizationCodeGrantIncluded
        )
        credentialOfferInfo.setIssuerStateIncluded(issuerStateIncluded)
        credentialOfferInfo.setIssuerState(issuerState)
        credentialOfferInfo.setPreAuthorizedCodeGrantIncluded(
          preAuthorizedCodeGrantIncluded
        )
        credentialOfferInfo.setPreAuthorizedCode(preAuthorizedCode)
        credentialOfferInfo.setSubject(subject)
        credentialOfferInfo.setExpiresAt(expiresAt)
        credentialOfferInfo.setContext(context)
        // credentialOfferInfo.setProperties(properties)
        credentialOfferInfo.setJwtAtClaims(jwtAtClaims)
        credentialOfferInfo.setAuthTime(authTime)
        credentialOfferInfo.setAcr(acr)
        credentialOfferInfo.setTxCode(txCode)
        credentialOfferInfo.setTxCodeInputMode(txCodeInputMode)
        credentialOfferInfo.setTxCodeDescription(txCodeDescription)
        credentialOfferInfo
      }
    }

  implicit val credentialRequestInfoDecoder: Decoder[CredentialRequestInfo] =
    Decoder.instance[CredentialRequestInfo] { h =>
      for {
        identifier  <- h.get[Option[String]]("identifier").map(_.orNull)
        format      <- h.get[Option[String]]("format").map(_.orNull)
        bindingKey  <- h.get[Option[String]]("bindingKey").map(_.orNull)
        bindingKeys <- h.get[Array[String]]("bindingKeys")
        details     <- h.get[Option[String]]("details").map(_.orNull)
      } yield {
        var credentialRequestInfo = CredentialRequestInfo()
        credentialRequestInfo.setIdentifier(identifier)
        credentialRequestInfo.setFormat(format)
        credentialRequestInfo.setBindingKey(bindingKey)
        credentialRequestInfo.setBindingKeys(bindingKeys)
        credentialRequestInfo.setDetails(details)
        credentialRequestInfo
      }
    }

  implicit val credentialIssuanceOrderDecoder: Decoder[CredentialIssuanceOrder] =
    Decoder.instance[CredentialIssuanceOrder] { h =>
      for {
        requestIdentifier  <- h.get[Option[String]]("requestIdentifier").map(_.orNull)
        credentialPayload  <- h.get[Option[String]]("credentialPayload").map(_.orNull)
        issuanceDeferred   <- h.get[Option[Boolean]]("issuanceDeferred").map(_.getOrElse(false))
        credentialDuration <- h.get[Option[Long]]("credentialDuration").map(_.getOrElse(0L))
        signingKeyId       <- h.get[Option[String]]("signingKeyId").map(_.orNull)
      } yield {
        var credentialIssuanceOrder = CredentialIssuanceOrder()
        credentialIssuanceOrder.setRequestIdentifier(requestIdentifier)
        credentialIssuanceOrder.setCredentialPayload(credentialPayload)
        credentialIssuanceOrder.setIssuanceDeferred(issuanceDeferred)
        credentialIssuanceOrder.setCredentialDuration(credentialDuration)
        credentialIssuanceOrder.setSigningKeyId(signingKeyId)
        credentialIssuanceOrder
      }
    }

  implicit val authorizationRequestEncoder: Encoder[AuthorizationRequest] =
    Encoder.instance[AuthorizationRequest] { req =>
      Json.obj(
        "parameters" -> Json.fromString(req.getParameters()),
        "context"    -> Json.fromString(req.getContext())
      )
    }

  implicit val authorizationResponseDecoder: Decoder[AuthorizationResponse] =
    Decoder.instance(h => {
      for {
        resultCode                   <- h.get[String]("resultCode")
        resultMessage                <- h.get[String]("resultCode")
        action                       <- h.get[Option[String]]("action").map(_.orNull)
        service                      <- h.get[Service]("service")
        client                       <- h.get[Client]("client")
        display                      <- h.get[Option[String]]("display").map(display => Display.valueOf(display.orNull))
        maxAge                       <- h.get[Option[Int]]("maxAge").map(_.getOrElse(0))
        scopes                       <- h.get[Array[Scope]]("scopes")
        dynamicScopes                <- h.get[Array[String]]("dynamicScopes")
        uiLocales                    <- h.get[Array[String]]("uiLocales")
        claimsLocales                <- h.get[Array[String]]("claimsLocales")
        claims                       <- h.get[Array[String]]("claims")
        claimsAtUserInfo             <- h.get[Array[String]]("claimsAtUserInfo")
        acrEssential                 <- h.get[Option[Boolean]]("acrEssential").map(_.getOrElse(false))
        clientIdAliasUsed            <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityIdUsed           <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        acrs                         <- h.get[Array[String]]("acrs")
        subject                      <- h.get[Option[String]]("subject").map(_.orNull)
        loginHint                    <- h.get[Option[String]]("loginHint").map(_.orNull)
        lowestPrompt                 <- h.get[Option[String]]("lowestPrompt").map(_.orNull)
        prompts                      <- h.get[Array[String]]("prompts")
        requestObjectPayload         <- h.get[Option[String]]("requestObjectPayload").map(_.orNull)
        idTokenClaims                <- h.get[Option[String]]("idTokenClaims").map(_.orNull)
        userInfoClaims               <- h.get[Option[String]]("userInfoClaims").map(_.orNull)
        transformedClaims            <- h.get[Option[String]]("transformedClaims").map(_.orNull)
        resources                    <- h.get[Array[URI]]("resources")
        authorizationDetails         <- h.get[AuthzDetails]("authorizationDetails")
        purpose                      <- h.get[Option[String]]("purpose").map(_.orNull)
        gmAction                     <- h.get[Option[String]]("gmAction").map(_.orNull)
        grantId                      <- h.get[Option[String]]("grantId").map(_.orNull)
        grantSubject                 <- h.get[Option[String]]("grantSubject").map(_.orNull)
        grant                        <- h.get[Grant]("grant")
        requestedClaimsForTx         <- h.get[Array[String]]("requestedClaimsForTx")
        requestedVerifiedClaimsForTx <- h.get[Array[String]]("requestedVerifiedClaimsForTx")
        credentialOfferInfo          <- h.get[CredentialOfferInfo]("credentialOfferInfo")
        issuableCredentials          <- h.get[Option[String]]("issuableCredentials").map(_.orNull)
        responseContent              <- h.get[Option[String]]("responseContent").map(_.orNull)
        ticket                       <- h.get[Option[String]]("ticket").map(_.orNull)
      } yield {
        var response = AuthorizationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(AuthorizationResponse.Action.valueOf(action))
        response.setMaxAge(maxAge)
        response.setScopes(scopes)

        response
      }
    })

  implicit val authorizationResponseEncoder: Encoder[AuthorizationResponse] =
    Encoder.instance[AuthorizationResponse] { resp =>
      Json.obj(
        "resultCode"    -> Json.fromString(resp.getResultCode()),
        "resultMessage" -> Json.fromString(resp.getResultMessage()),
        "action"        -> Json.fromString(resp.getAction().toString()),
        "maxAge"        -> Json.fromInt(resp.getMaxAge()),
        /// "scopes" -> Json.arr(reqgetScopes().map(Json.fromString): _*),
        "claims" -> Json.arr(resp.getClaims().map(Json.fromString)*), // _*
        "claimsAtUserInfo" -> Json.arr(
          resp.getClaimsAtUserInfo().map(Json.fromString)* // _*
        ),
        "acrEssential"   -> Json.fromBoolean(resp.isAcrEssential()),
        "acrs"           -> Json.arr(resp.getAcrs().map(Json.fromString)*), // _*
        "subject"        -> Json.fromString(resp.getSubject()),
        "idTokenClaims"  -> Json.fromString(resp.getIdTokenClaims()),
        "userInfoClaims" -> Json.fromString(resp.getUserInfoClaims())
      )
    }

  implicit val authorizationFailRequestEncoder: Encoder[AuthorizationFailRequest] =
    Encoder.instance[AuthorizationFailRequest] { req =>
      Json.obj(
        "ticket"      -> Json.fromString(req.getTicket()),
        "reason"      -> Json.fromString(req.getReason().toString()),
        "description" -> Json.fromString(req.getDescription())
      )
    }

  implicit val authorizationFailResponseDecoder: Decoder[AuthorizationFailResponse] = Decoder
    .instance { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = AuthorizationFailResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(AuthorizationFailResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response

      }
    }

  implicit val authorizationFailResponseEncoder: Encoder[AuthorizationFailResponse] =
    Encoder.instance[AuthorizationFailResponse] { resp =>
      Json.obj(
        "resultCode"      -> Json.fromString(resp.getResultCode()),
        "resultMessage"   -> Json.fromString(resp.getResultMessage()),
        "action"          -> Json.fromString(resp.getAction().toString()),
        "responseContent" -> Json.fromString(resp.getResponseContent())
      )
    }

  implicit val authorizationIssueRequestEncoder: Encoder[AuthorizationIssueRequest] =
    Encoder.instance[AuthorizationIssueRequest] { req =>
      Json.obj(
        "ticket"   -> Json.fromString(req.getTicket()),
        "subject"  -> Json.fromString(req.getSubject()),
        "sub"      -> Json.fromString(req.getSub()),
        "authTime" -> Json.fromLong(req.getAuthTime()),
        "acr"      -> Json.fromString(req.getAcr()),
        "claims"   -> Json.fromString(req.getClaims()),
        "properties" -> Json.arr(
          req
            .getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue()))): _*
        ), // The Json.arr method expects a variable number of Json arguments. By using : _*, you can convert the array to a variable argument list.
        "scopes"          -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "idtHeaderParams" -> Json.fromString(req.getIdtHeaderParams()),
        "authorizationDetails" -> authzDetailsEncoder(
          req.getAuthorizationDetails()
        ),
        "consentedClaims" -> Json.fromValues(
          req.getConsentedClaims().map(Json.fromString)
        ),
        "claimsForTx" -> Json.fromString(req.getClaimsForTx()),
        "verifiedClaimsForTx" -> Json.fromValues(
          req.getVerifiedClaimsForTx().map(Json.fromString)
        ),
        "jwtAtClaims"         -> Json.fromString(req.getJwtAtClaims()),
        "accessToken"         -> Json.fromString(req.getAccessToken()),
        "idTokenAudType"      -> Json.fromString(req.getIdTokenAudType()),
        "accessTokenDuration" -> Json.fromLong(req.getAccessTokenDuration())
      )
    }

  implicit val authorizationIssueResponseEncoder: Encoder[AuthorizationIssueResponse] =
    Encoder.instance[AuthorizationIssueResponse] { resp =>
      Json.obj(
        "resultCode"           -> Json.fromString(resp.getResultCode()),
        "resultMessage"        -> Json.fromString(resp.getResultMessage()),
        "action"               -> Json.fromString(resp.getAction().toString()),
        "responseContent"      -> Json.fromString(resp.getResponseContent()),
        "accessToken"          -> Json.fromString(resp.getAccessToken()),
        "accessTokenExpiresAt" -> Json.fromLong(resp.getAccessTokenExpiresAt()),
        "accessTokenDuration"  -> Json.fromLong(resp.getAccessTokenDuration()),
        "idToken"              -> Json.fromString(resp.getIdToken()),
        "authorizationCode"    -> Json.fromString(resp.getAuthorizationCode()),
        "jwtAccessToken"       -> Json.fromString(resp.getJwtAccessToken()),
        "ticketInfo"           -> Json.fromString(resp.getTicketInfo().getContext())
      )
    }

  implicit val authorizationIssueResponseDecoder: Decoder[AuthorizationIssueResponse] =
    Decoder.instance[AuthorizationIssueResponse] { h =>
      for {
        resultCode           <- h.get[String]("resultCode")
        resultMessage        <- h.get[String]("resultCode")
        action               <- h.get[Option[String]]("action").map(_.orNull)
        responseContent      <- h.get[Option[String]]("responseContent").map(_.orNull)
        accessToken          <- h.get[Option[String]]("accessToken").map(_.orNull)
        accessTokenExpiresAt <- h.get[Option[Long]]("accessTokenExpiresAt").map(_.getOrElse(0L))
        accessTokenDuration  <- h.get[Option[Long]]("accessTokenDuration").map(_.getOrElse(0L))
        idToken              <- h.get[Option[String]]("idToken").map(_.orNull)
        authorizationCode    <- h.get[Option[String]]("authorizationCode").map(_.orNull)
        jwtAccessToken       <- h.get[Option[String]]("jwtAccessToken").map(_.orNull)
        ticketInfo <-
          h.get[Option[String]]("ticketInfo")
            .map(ticketInfo => AuthorizationTicketInfo().setContext(ticketInfo.orNull))
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
        response.setTicketInfo(ticketInfo)
        response
      }
    }

  implicit val tokenRequestEncoder: Encoder[TokenRequest] =
    Encoder.instance[TokenRequest] { req =>
      Json.obj(
        "parameters"        -> Json.fromString(req.getParameters()),
        "clientId"          -> Json.fromString(req.getClientId()),
        "clientSecret"      -> Json.fromString(req.getClientSecret()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "clientCertificatePath" -> Json.arr(
          req.getClientCertificatePath().map(Json.fromString)*
        ),
        "properties" -> Json.fromValues(
          req
            .getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue())))
        ),
        "dpop"                 -> Json.fromString(req.getDpop()),
        "htm"                  -> Json.fromString(req.getHtm()),
        "htu"                  -> Json.fromString(req.getHtu()),
        "jwtAtClaims"          -> Json.fromString(req.getJwtAtClaims()),
        "accessToken"          -> Json.fromString(req.getAccessToken()),
        "accessTokenDuration"  -> Json.fromLong(req.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(req.getRefreshTokenDuration()),
        "dpopNonceRequired"    -> Json.fromBoolean(req.isDpopNonceRequired()),
        "oauthClientAttestation" -> Json.fromString(
          req.getOauthClientAttestation()
        )
      )
    }

  implicit val tokenResponseDecoder: Decoder[TokenResponse] = Decoder.instance { h =>
    for {
      resultCode            <- h.get[String]("resultCode")
      resultMessage         <- h.get[String]("resultCode")
      action                <- h.get[Option[String]]("action").map(_.orNull)
      clientId              <- h.get[Option[String]]("clientId").map(_.orNull)
      accessToken           <- h.get[Option[String]]("accessToken").map(_.orNull)
      accessTokenExpiresAt  <- h.get[Option[Long]]("accessTokenExpiresAt").map(_.getOrElse(0L))
      accessTokenDuration   <- h.get[Option[Long]]("accessTokenDuration").map(_.getOrElse(0L))
      refreshToken          <- h.get[Option[String]]("refreshToken").map(_.orNull)
      refreshTokenExpiresAt <- h.get[Option[Long]]("refreshTokenExpiresAt").map(_.getOrElse(0L))
      refreshTokenDuration  <- h.get[Option[Long]]("refreshTokenDuration").map(_.getOrElse(0L))
      idToken               <- h.get[Option[String]]("idToken").map(_.orNull)
      jwtAccessToken        <- h.get[Option[String]]("jwtAccessToken").map(_.orNull)
      properties            <- h.get[List[String]]("properties") // .map()
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

  implicit val tokenCreateRequestEncoder: Encoder[TokenCreateRequest] =
    Encoder.instance[TokenCreateRequest] { req =>
      Json.obj(
        "grantType"            -> Json.fromString(req.getGrantType().toString()),
        "clientId"             -> Json.fromString(req.getClientId().toString()),
        "subject"              -> Json.fromString(req.getSubject()),
        "scopes"               -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "accessTokenDuration"  -> Json.fromLong(req.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(req.getRefreshTokenDuration()),
        "properties" -> Json.fromValues(
          req
            .getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue())))
        ),
        "clientIdAliasUsed"  -> Json.fromBoolean(req.isClientIdAliasUsed()),
        "clientEntityIdUsed" -> Json.fromBoolean(req.isClientEntityIdUsed()),
        "accessToken"        -> Json.fromString(req.getAccessToken()),
        "refreshToken"       -> Json.fromString(req.getRefreshToken()),
        "accessTokenPersistent" -> Json.fromBoolean(
          req.isAccessTokenPersistent()
        ),
        "certificateThumbprint" -> Json.fromString(
          req.getCertificateThumbprint()
        ),
        "dpopKeyThumbprint" -> Json.fromString(req.getDpopKeyThumbprint()),
        "authorizationDetails" -> authzDetailsEncoder(
          req.getAuthorizationDetails()
        ),
        "resources" -> Json.fromValues(
          req.getResources().map(uri => Json.fromString(uri.toString()))
        ),
        "forExternalAttachment" -> Json.fromBoolean(
          req.isForExternalAttachment()
        ),
        "jwtAtClaims"      -> Json.fromString(req.getJwtAtClaims()),
        "acr"              -> Json.fromString(req.getAcr()),
        "authTime"         -> Json.fromLong(req.getAuthTime()),
        "clientIdentifier" -> Json.fromString(req.getClientIdentifier())
      )
    }

  implicit val tokenCreateResponseDecoder: Decoder[TokenCreateResponse] =
    Decoder.instance[TokenCreateResponse] { h =>
      for {
        resultCode           <- h.get[String]("resultCode")
        resultMessage        <- h.get[String]("resultCode")
        action               <- h.get[Option[String]]("action").map(_.orNull)
        grantType            <- h.get[Option[String]]("grantType").map(_.orNull)
        clientId             <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        subject              <- h.get[Option[String]]("subject").map(_.orNull)
        scopes               <- h.get[Array[String]]("scopes")
        accessToken          <- h.get[Option[String]]("accessToken").map(_.orNull)
        tokenType            <- h.get[Option[String]]("tokenType").map(_.orNull)
        expiresIn            <- h.get[Option[Long]]("expiresIn").map(_.getOrElse(0L))
        expiresAt            <- h.get[Option[Long]]("expiresAt").map(_.getOrElse(0L))
        refreshToken         <- h.get[Option[String]]("refreshToken").map(_.orNull)
        properties           <- h.get[List[String]]("properties")
        jwtAccessToken       <- h.get[Option[String]]("jwtAccessToken").map(_.orNull)
        authorizationDetails <- h.get[AuthzDetails]("authorizationDetails")
        forExternalAttachment <-
          h.get[Option[Boolean]]("forExternalAttachment").map(_.getOrElse(false))
        tokenId            <- h.get[Option[String]]("tokenId").map(_.orNull)
        refreshTokenScopes <- h.get[Array[String]]("refreshTokenScopes")
        clientIdentifier   <- h.get[Option[String]]("clientIdentifier").map(_.orNull)
      } yield {
        var response = TokenCreateResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(TokenCreateResponse.Action.valueOf(action))
        response.setGrantType(GrantType.valueOf(grantType))
        response.setClientId(clientId)
        response.setSubject(subject)
        response.setScopes(scopes)
        response.setAccessToken(accessToken)
        response.setTokenType(tokenType)
        response.setExpiresIn(expiresIn)
        response.setExpiresAt(expiresAt)
        response.setRefreshToken(refreshToken)
        // response.setProperties(properties)
        response.setJwtAccessToken(jwtAccessToken)
        response.setAuthorizationDetails(authorizationDetails)
        response.setForExternalAttachment(forExternalAttachment)
        response.setTokenId(tokenId)
        response.setRefreshTokenScopes(refreshTokenScopes)
        response.setClientIdentifier(clientIdentifier)
        response
      }
    }

  implicit val tokenFailRequestEncoder: Encoder[TokenFailRequest] =
    Encoder[TokenFailRequest] { req =>
      Json.obj(
        "ticket" -> Json.fromString(req.getTicket()),
        "reason" -> Json.fromString(req.getReason().toString())
      )
    }

  implicit val tokenFailResponseDecoder: Decoder[TokenFailResponse] =
    Decoder[TokenFailResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = TokenFailResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(TokenFailResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val tokenIssueRequestEncoder: Encoder[TokenIssueRequest] =
    Encoder[TokenIssueRequest] { req =>
      Json.obj(
        "ticket"  -> Json.fromString(req.getTicket()),
        "subject" -> Json.fromString(req.getSubject()),
        "properties" -> Json.fromValues(
          req
            .getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue())))
        ),
        "jwtAtClaims"          -> Json.fromString(req.getJwtAtClaims()),
        "accessToken"          -> Json.fromString(req.getAccessToken()),
        "accessTokenDuration"  -> Json.fromLong(req.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(req.getRefreshTokenDuration())
      )
    }

  implicit val tokenIssueResponseDecoder: Decoder[TokenIssueResponse] =
    Decoder[TokenIssueResponse] { h =>
      for {
        resultCode            <- h.get[String]("resultCode")
        resultMessage         <- h.get[String]("resultCode")
        action                <- h.get[Option[String]]("action").map(_.orNull)
        responseContent       <- h.get[Option[String]]("responseContent").map(_.orNull)
        accessToken           <- h.get[Option[String]]("accessToken").map(_.orNull)
        accessTokenExpiresAt  <- h.get[Option[Long]]("accessTokenExpiresAt").map(_.getOrElse(0L))
        accessTokenDuration   <- h.get[Option[Long]]("accessTokenDuration").map(_.getOrElse(0L))
        refreshToken          <- h.get[Option[String]]("refreshToken").map(_.orNull)
        refreshTokenExpiresAt <- h.get[Option[Long]]("refreshTokenExpiresAt").map(_.getOrElse(0L))
        refreshTokenDuration  <- h.get[Option[Long]]("refreshTokenDuration").map(_.getOrElse(0L))
        clientId              <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        clientIdAlias         <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed     <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId        <- h.get[URI]("clientEntityId")
        clientEntityIdUsed    <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        subject               <- h.get[Option[String]]("subject").map(_.orNull)
        scopes                <- h.get[Array[String]]("scopes")
        properties            <- h.get[Array[String]]("properties")
        jwtAccessToken        <- h.get[Option[String]]("jwtAccessToken").map(_.orNull)
        accessTokenResources  <- h.get[Array[URI]]("accessTokenResources")
        authorizationDetails  <- h.get[AuthzDetails]("authorizationDetails")
        serviceAttributes     <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes      <- h.get[Array[Pair]]("clientAttributes")
        refreshTokenScopes    <- h.get[Array[String]]("refreshTokenScopes")
      } yield {
        var response = TokenIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(TokenIssueResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setAccessToken(accessToken)
        response.setAccessTokenExpiresAt(accessTokenExpiresAt)
        response.setAccessTokenDuration(accessTokenDuration)
        response.setRefreshToken(refreshToken)
        response.setRefreshTokenExpiresAt(refreshTokenExpiresAt)
        response.setRefreshTokenDuration(refreshTokenDuration)
        response.setClientId(clientId)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed(clientIdAliasUsed)
        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setSubject(subject)
        response.setScopes(scopes)
        // response.setProperties(properties)
        response.setJwtAccessToken(jwtAccessToken)

        response.setAccessTokenResources(accessTokenResources)

        response.setAuthorizationDetails(authorizationDetails)

        response.setServiceAttributes(serviceAttributes)

        response.setClientAttributes(clientAttributes)

        response.setRefreshTokenScopes(refreshTokenScopes)
        response

      }
    }

  implicit val tokenRevokeRequestEncoder: Encoder[TokenRevokeRequest] =
    Encoder.instance[TokenRevokeRequest] { req =>
      Json.obj(
        "accessTokenIdentifier" -> Json.fromString(req.getClientIdentifier()),
        "refreshTokenIdentifier" -> Json.fromString(
          req.getRefreshTokenIdentifier()
        ),
        "clientIdentifier" -> Json.fromString(req.getClientIdentifier()),
        "subject"          -> Json.fromString(req.getSubject())
      )

    }

  implicit val tokenRevokeResponseDecoder: Decoder[TokenRevokeResponse] =
    Decoder.instance[TokenRevokeResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        count         <- h.get[Option[Int]]("count").map(_.getOrElse(0))
      } yield {
        var response = new TokenRevokeResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setCount(count)
        response
      }

    }

  implicit val tokenUpdateRequestEncoder: Encoder[TokenUpdateRequest] =
    Encoder.instance[TokenUpdateRequest] { req =>
      Json.obj(
        "accessToken"          -> Json.fromString(req.getAccessToken()),
        "accessTokenExpiresAt" -> Json.fromLong(req.getAccessTokenExpiresAt()),
        "refreshTokenExpiresAt" -> Json.fromLong(
          req.getRefreshTokenExpiresAt()
        ),
        "scopes" -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "properties" -> Json.fromValues(
          req
            .getProperties()
            .map(prop => Json.obj(prop.getKey() -> Json.fromString(prop.getValue())))
        ),
        "accessTokenExpiresAtUpdatedOnScopeUpdate" -> Json.fromBoolean(
          req.isAccessTokenExpiresAtUpdatedOnScopeUpdate()
        ),
        "refreshTokenExpiresAtUpdatedOnScopeUpdate" -> Json.fromBoolean(
          req.isRefreshTokenExpiresAtUpdatedOnScopeUpdate()
        ),
        "accessTokenPersistent" -> Json.fromBoolean(
          req.isAccessTokenPersistent()
        ),
        "accessTokenHash" -> Json.fromString(req.getAccessTokenHash()),
        "accessTokenValueUpdated" -> Json.fromBoolean(
          req.isAccessTokenValueUpdated()
        ),
        "certificateThumbprint" -> Json.fromString(
          req.getCertificateThumbprint()
        ),
        "dpopKeyThumbprint" -> Json.fromString(req.getDpopKeyThumbprint()),
        "authorizationDetails" -> authzDetailsEncoder(
          req.getAuthorizationDetails()
        ),
        "forExternalAttachment" -> Json.fromBoolean(
          req.isForExternalAttachment()
        ),
        "tokenId" -> Json.fromString(req.getTokenId())
      )
    }

  implicit val tokenUpdateResponseDecoder: Decoder[TokenUpdateResponse] =
    Decoder.instance[TokenUpdateResponse] { h =>
      for {
        resultCode            <- h.get[String]("resultCode")
        resultMessage         <- h.get[String]("resultCode")
        action                <- h.get[Option[String]]("action").map(_.orNull)
        accessToken           <- h.get[Option[String]]("accessToken").map(_.orNull)
        tokenType             <- h.get[Option[String]]("tokenType").map(_.orNull)
        accessTokenExpiresAt  <- h.get[Option[Long]]("accessTokenExpiresAt").map(_.getOrElse(0L))
        refreshTokenExpiresAt <- h.get[Option[Long]]("refreshTokenExpiresAt").map(_.getOrElse(0L))
        scopes                <- h.get[Array[String]]("scopes")
        properties            <- h.get[Array[String]]("properties")
        authorizationDetails  <- h.get[AuthzDetails]("authorizationDetails")
        forExternalAttachment <-
          h.get[Option[Boolean]]("forExternalAttachment").map(_.getOrElse(false))
        tokenId <- h.get[Option[String]]("tokenId").map(_.orNull)
      } yield {
        var response = TokenUpdateResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(TokenUpdateResponse.Action.valueOf(action))
        response.setAccessToken(accessToken)
        response.setTokenType(tokenType)
        response.setAccessTokenExpiresAt(accessTokenExpiresAt)
        response.setRefreshTokenExpiresAt(refreshTokenExpiresAt)
        response.setScopes(scopes)
        // response.setProperties(properties)
        response.setAuthorizationDetails(authorizationDetails)
        response.setForExternalAttachment(forExternalAttachment)
        response.setTokenId(tokenId)
        response
      }
    }

  implicit val tokenListResponseEncoder: Encoder[TokenListResponse] =
    Encoder.instance[TokenListResponse] { resp =>
      Json.obj(
        "start"      -> Json.fromInt(resp.getStart()),
        "end"        -> Json.fromInt(resp.getEnd()),
        "client"     -> clientEncoder(resp.getClient()),
        "subject"    -> Json.fromString(resp.getSubject()),
        "totalCount" -> Json.fromInt(resp.getTotalCount()),
        "accessTokens" -> Json.fromValues(
          resp.getAccessTokens().map(accessTokenEncoder.apply)
        )
      )
    }

  implicit val tokenListResponseDecoder: Decoder[TokenListResponse] =
    Decoder.instance[TokenListResponse] { h =>
      for {
        start        <- h.get[Option[Int]]("start").map(_.getOrElse(0))
        ed           <- h.get[Option[Int]]("end").map(_.getOrElse(0))
        client       <- h.get[Client]("client")
        subject      <- h.get[Option[String]]("subject").map(_.orNull)
        totalCount   <- h.get[Option[Int]]("totalCount").map(_.getOrElse(0))
        accessTokens <- h.get[Array[AccessToken]]("accessTokens")
      } yield {
        var response = TokenListResponse()
        response.setStart(start)
        response.setEnd(ed)
        response.setClient(client)
        response.setSubject(subject)
        response.setTotalCount(totalCount)
        response.setAccessTokens(accessTokens)
        response
      }
    }

  implicit val revocationRequestEncoder: Encoder[RevocationRequest] =
    Encoder.instance[RevocationRequest] { req =>
      Json.obj(
        "parameters"        -> Json.fromString(req.getParameters()),
        "clientId"          -> Json.fromString(req.getClientId()),
        "clientSecret"      -> Json.fromString(req.getClientSecret()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "clientCertificatePath" -> Json.arr(
          req.getClientCertificatePath().map(Json.fromString)* // _*
        ),
        "oauthClientAttestation" -> Json.fromString(
          req.getOauthClientAttestation()
        ),
        "oauthClientAttestationPop" -> Json.fromString(
          req.getOauthClientAttestationPop()
        )
      )
    }

  implicit val revocationResponseDecoder: Decoder[RevocationResponse] =
    Decoder.instance { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)

      } yield {
        var response = RevocationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(RevocationResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val RevocationResponseEncoder: Encoder[RevocationResponse] =
    Encoder.instance[RevocationResponse] { resp =>
      Json.obj(
        "resultCode"      -> Json.fromString(resp.getResultCode()),
        "resultMessage"   -> Json.fromString(resp.getResultMessage()),
        "action"          -> Json.fromString(resp.getAction().toString()),
        "responseContent" -> Json.fromString(resp.getResponseContent())
      )
    }

  implicit val userInfoRequestEncoder: Encoder[UserInfoRequest] =
    Encoder.instance[UserInfoRequest] { req =>
      Json.obj(
        "token"             -> Json.fromString(req.getToken()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "dpop"              -> Json.fromString(req.getDpop()),
        "htm"               -> Json.fromString(req.getHtm()),
        "htu"               -> Json.fromString(req.getHtu()),
        // "uri" -> Json.fromString(req.getUri()),
        "targetUri" -> Json.fromString(req.getTargetUri().toString()),
        "headers"   -> Json.fromValues(req.getHeaders().map(pairEncoder.apply)),
        // "message" -> Json.fromString(req.getMessage()),
        "requestBodyContained" -> Json.fromBoolean(
          req.isRequestBodyContained()
        ),
        "dpopNonceRequired" -> Json.fromBoolean(req.isDpopNonceRequired())
      )

    }

  implicit val userInfoResponseDecoder: Decoder[UserInfoResponse] =
    Decoder.instance[UserInfoResponse] { h =>
      for {
        resultCode           <- h.get[String]("resultCode")
        resultMessage        <- h.get[String]("resultCode")
        action               <- h.get[Option[String]]("action").map(_.orNull)
        clientId             <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        subject              <- h.get[Option[String]]("subject").map(_.orNull)
        scopes               <- h.get[Array[String]]("scopes")
        claims               <- h.get[Array[String]]("claims")
        token                <- h.get[Option[String]]("token").map(_.orNull)
        responseContent      <- h.get[Option[String]]("responseContent").map(_.orNull)
        properties           <- h.get[Array[String]]("properties")
        clientIdAlias        <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed    <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId       <- h.get[URI]("clientEntityId")
        clientEntityIdUsed   <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        userInfoClaims       <- h.get[Option[String]]("userInfoClaims").map(_.orNull)
        transformedClaims    <- h.get[Option[String]]("transformedClaims").map(_.orNull)
        consentedClaims      <- h.get[Array[String]]("consentedClaims")
        requestedClaimsForTx <- h.get[Array[String]]("requestedClaimsForTx")
        // requestedVerifiedClaimsForTx <- h.get[Array[StringArray]]("requestedVerifiedClaimsForTx")
        serviceAttributes <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes  <- h.get[Array[Pair]]("clientAttributes")
        dpopNonce         <- h.get[Option[String]]("dpopNonce").map(_.orNull)
      } yield {
        var response = UserInfoResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(UserInfoResponse.Action.valueOf(action))
        response.setClientId(clientId)
        response.setSubject(subject)
        response.setScopes(scopes)
        response.setClaims(claims)
        response.setToken(token)
        response.setResponseContent(responseContent)
        // response.setProperties(properties)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed(clientIdAliasUsed)
        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setUserInfoClaims(userInfoClaims)
        response.setTransformedClaims(transformedClaims)
        response.setConsentedClaims(consentedClaims)
        response.setRequestedClaimsForTx(requestedClaimsForTx)
        // response.setRequestedVerifiedClaimsForTx(requestedVerifiedClaimsForTx)
        response.setServiceAttributes(serviceAttributes)
        response.setClientAttributes(clientAttributes)
        response.setDpopNonce(dpopNonce)
        response
      }

    }

  implicit val userinfoIusseRequestEncoder: Encoder[UserInfoIssueRequest] =
    Encoder.instance[UserInfoIssueRequest] { req =>
      Json.obj(
        "token"       -> Json.fromString(req.getToken()),
        "claims"      -> Json.fromString(req.getClaims()),
        "sub"         -> Json.fromString(req.getSub()),
        "claimsForTx" -> Json.fromString(req.getClaimsForTx()),
        "verifiedClaimsForTx" -> Json.fromValues(
          req.getVerifiedClaimsForTx().map(Json.fromString)
        ),
        "requestSignature" -> Json.fromString(req.getRequestSignature()),
        "headers"          -> Json.fromValues(req.getHeaders().map(pairEncoder.apply))
      )

    }

  implicit val userInfoIssueResponseDecoder: Decoder[UserInfoIssueResponse] =
    Decoder.instance[UserInfoIssueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        signature       <- h.get[Option[String]]("signature").map(_.orNull)
        signatureInput  <- h.get[Option[String]]("signatureInput").map(_.orNull)
        contentDigest   <- h.get[Option[String]]("contentDigest").map(_.orNull)
      } yield {
        var response = UserInfoIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(UserInfoIssueResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setSignature(signature)
        response.setSignatureInput(signatureInput)
        response.setContentDigest(contentDigest)
        response
      }
    }

  implicit val introspectionRequestEncoder: Encoder[IntrospectionRequest] =
    Encoder.instance[IntrospectionRequest] { req =>
      Json.obj(
        "token"             -> Json.fromString(req.getToken()),
        "scopes"            -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "subject"           -> Json.fromString(req.getSubject()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "dpop"              -> Json.fromString(req.getDpop()),
        "htm"               -> Json.fromString(req.getHtm()),
        "htu"               -> Json.fromString(req.getHtu()),
        "resources" -> Json.fromValues(
          req.getResources().map(uri => Json.fromString(uri.toString()))
        ),
        // "uri" -> Json.fromString(req.getUri()),
        "targetUri" -> Json.fromString(req.getTargetUri().toString()),
        // "message" -> Json.fromString(req.getMessage()),
        "headers" -> Json.fromValues(req.getHeaders().map(pairEncoder.apply)),
        "requestBodyContained" -> Json.fromBoolean(
          req.isRequestBodyContained()
        ),
        // "requiredComponents" -> Json.fromValues(
        //   req.getRequiredComponents().map(Json.fromString)
        // ),
        "acrValues"         -> Json.fromValues(req.getAcrValues().map(Json.fromString)),
        "maxAge"            -> Json.fromInt(req.getMaxAge()),
        "dpopNonceRequired" -> Json.fromBoolean(req.isDpopNonceRequired())
      )
    }

  implicit val introspectionResponseEncoder: Encoder[IntrospectionResponse] =
    Encoder.instance[IntrospectionResponse] { resp =>
      Json.obj(
        "resultCode"    -> Json.fromString(resp.getResultCode()),
        "resultMessage" -> Json.fromString(resp.getResultMessage()),
        "action"        -> Json.fromString(resp.getAction().toString()),
        "clientId"      -> Json.fromLong(resp.getClientId()),
        "subject"       -> Json.fromString(resp.getSubject()),
        "scopes"        -> Json.fromValues(resp.getScopes().map(Json.fromString)),
        "scopeDetails" -> Json.fromValues(
          resp.getScopeDetails().map(scope => Json.fromString(scope.getName()))
        ),
        "existent"        -> Json.fromBoolean(resp.isExistent()),
        "usable"          -> Json.fromBoolean(resp.isUsable()),
        "sufficient"      -> Json.fromBoolean(resp.isSufficient()),
        "refreshable"     -> Json.fromBoolean(resp.isRefreshable()),
        "responseContent" -> Json.fromString(resp.getResponseContent()),
        "expiresAt"       -> Json.fromLong(resp.getExpiresAt()),
        // "properties" -> Json.fromValues(resp.getProperties().map()),
        "clientIdAlias"     -> Json.fromString(resp.getClientIdAlias()),
        "clientIdAliasUsed" -> Json.fromBoolean(resp.isClientIdAliasUsed()),
        "clientEntityId" -> Json.fromString(
          resp.getClientEntityId().toString()
        ),
        "clientEntityIdUsed" -> Json.fromBoolean(resp.isClientEntityIdUsed()),
        "certificateThumbprint" -> Json.fromString(
          resp.getCertificateThumbprint()
        ),
        "resources" -> Json.fromValues(
          resp.getResources().map(uri => Json.fromString(uri.toString()))
        ),
        "accessTokenResources" -> Json.fromValues(
          resp.getAccessTokenResources().map(uri => Json.fromString(uri.toString()))
        ),
        "authorizationDetails" -> authzDetailsEncoder(
          resp.getAuthorizationDetails()
        ),
        "grantId" -> Json.fromString(resp.getGrantId()),
        "consentedClaims" -> Json.fromValues(
          resp.getConsentedClaims().map(Json.fromString)
        ),
        "serviceAttributes" -> Json.fromValues(
          resp.getServiceAttributes().map(pairEncoder.apply)
        ),
        "clientAttributes" -> Json.fromValues(
          resp.getClientAttributes().map(pairEncoder.apply)
        ),
        "forExternalAttachment" -> Json.fromBoolean(
          resp.isForExternalAttachment()
        ),
        "acr"       -> Json.fromString(resp.getAcr()),
        "authTime"  -> Json.fromLong(resp.getAuthTime()),
        "grantType" -> Json.fromString(resp.getGrantType().toString()),
        "forCredentialIssuance" -> Json.fromBoolean(
          resp.isForCredentialIssuance()
        ),
        "cnonce"              -> Json.fromString(resp.getCnonce()),
        "cnonceExpiresAt"     -> Json.fromLong(resp.getCnonceExpiresAt()),
        "issuableCredentials" -> Json.fromString(resp.getIssuableCredentials()),
        "dpopNonce"           -> Json.fromString(resp.getDpopNonce()),
        "responseSigningRequired" -> Json.fromBoolean(
          resp.isResponseSigningRequired()
        )
      )
    }

  implicit val introspectionResponseDecoder: Decoder[IntrospectionResponse] =
    Decoder.instance { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        clientId        <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        subject         <- h.get[Option[String]]("subject").map(_.orNull)
        scopes          <- h.get[Option[Array[String]]]("scopes")
        scopeDetails    <- h.get[Array[Scope]]("scopeDetails")
        existent        <- h.get[Option[Boolean]]("existent").map(_.getOrElse(false))
        usable          <- h.get[Option[Boolean]]("usable").map(_.getOrElse(false))
        sufficient      <- h.get[Option[Boolean]]("sufficient").map(_.getOrElse(false))
        refreshable     <- h.get[Option[Boolean]]("refreshable").map(_.getOrElse(false))
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        expiresAt       <- h.get[Option[Long]]("expiresAt").map(_.getOrElse(0L))
        // properties <- h.get[Array[Property]]("properties")
        clientIdAlias         <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed     <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId        <- h.get[URI]("clientEntityId")
        clientEntityIdUsed    <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        certificateThumbprint <- h.get[Option[String]]("certificateThumbprint").map(_.orNull)
        resources             <- h.get[Array[URI]]("resources")
        accessTokenResources  <- h.get[Array[URI]]("accessTokenResources")
        authorizationDetails  <- h.get[AuthzDetails]("authorizationDetails")
        grantId               <- h.get[Option[String]]("grantId").map(_.orNull)
        consentedClaims       <- h.get[Array[String]]("consentedClaims")
        serviceAttributes     <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes      <- h.get[Array[Pair]]("clientAttributes")
        forExternalAttachment <-
          h.get[Option[Boolean]]("forExternalAttachment").map(_.getOrElse(false))
        acr       <- h.get[Option[String]]("acr").map(_.orNull)
        authTime  <- h.get[Option[Long]]("authTime").map(_.getOrElse(0L))
        grantType <- h.get[Option[String]]("grantType").map(_.orNull)
        forCredentialIssuance <-
          h.get[Option[Boolean]]("forCredentialIssuance").map(_.getOrElse(false))
        cnonce              <- h.get[Option[String]]("cnonce").map(_.orNull)
        cnonceExpiresAt     <- h.get[Option[Long]]("cnonceExpiresAt").map(_.getOrElse(0L))
        issuableCredentials <- h.get[Option[String]]("issuableCredentials").map(_.orNull)
        dpopNonce           <- h.get[Option[String]]("dpopNonce").map(_.orNull)
        responseSigningRequired <-
          h.get[Option[Boolean]]("responseSigningRequired").map(_.getOrElse(false))
      } yield {
        var response = IntrospectionResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(IntrospectionResponse.Action.valueOf(action))
        response.setClientId(clientId)
        response.setSubject(subject)

        response.setScopes(scopes.orNull)
        response.setScopeDetails(scopeDetails)

        response.setExistent(existent)

        response.setUsable(usable)

        response.setSufficient(sufficient)

        response.setRefreshable(refreshable)

        response.setResponseContent(responseContent)

        response.setExpiresAt(expiresAt)

        // response.setProperties(properties)

        response.setClientIdAlias(clientIdAlias)

        response.setClientIdAliasUsed(clientIdAliasUsed)

        response.setClientEntityId(clientEntityId)

        response.setClientEntityIdUsed(clientEntityIdUsed)

        response.setCertificateThumbprint(certificateThumbprint)

        response.setResources(resources)

        response.setAccessTokenResources(accessTokenResources)

        response.setAuthorizationDetails(authorizationDetails)

        response.setGrantId(grantId)

        response.setConsentedClaims(consentedClaims)

        response.setServiceAttributes(serviceAttributes)

        response.setClientAttributes(clientAttributes)

        response.setForExternalAttachment(forExternalAttachment)

        response.setAcr(acr)

        response.setAuthTime(authTime)

        response.setGrantType(GrantType.valueOf(grantType))

        response.setForCredentialIssuance(forCredentialIssuance)

        response.setCnonce(cnonce)

        response.setCnonceExpiresAt(cnonceExpiresAt)

        response.setIssuableCredentials(issuableCredentials)

        response.setDpopNonce(dpopNonce)

        response.setResponseSigningRequired(responseSigningRequired)

        response

      }

    }

  implicit val standardIntrospectionRequestEncoder: Encoder[StandardIntrospectionRequest] =
    Encoder.instance[StandardIntrospectionRequest] { req =>
      Json.obj(
        "parameters" -> Json.fromString(req.getParameters()),
        "withHiddenProperties" -> Json.fromBoolean(
          req.isWithHiddenProperties()
        ),
        "rsUri"            -> Json.fromString(req.getRsUri().toString()),
        "httpAcceptHeader" -> Json.fromString(req.getHttpAcceptHeader()),
        "introspectionSignAlg" -> Json.fromString(
          req.getIntrospectionSignAlg().toString()
        ),
        "introspectionEncryptionAlg" -> Json.fromString(
          req.getIntrospectionEncryptionAlg().toString()
        ),
        "introspectionEncryptionEnc" -> Json.fromString(
          req.getIntrospectionEncryptionEnc().toString()
        ),
        "sharedKeyForSign" -> Json.fromString(req.getSharedKeyForSign()),
        "sharedKeyForEncryption" -> Json.fromString(
          req.getSharedKeyForEncryption()
        ),
        "publicKeyForEncryption" -> Json.fromString(
          req.getPublicKeyForEncryption()
        )
      )
    }

  implicit val standardIntrospectionResponseDecoder: Decoder[StandardIntrospectionResponse] =
    Decoder.instance[StandardIntrospectionResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)

      } yield {
        var response = StandardIntrospectionResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(StandardIntrospectionResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val serviceEncoder: Encoder[Service] = Encoder.instance[Service] { s =>
    ???
  }

  implicit val serviceDecoder: Decoder[Service] = Decoder.instance[Service] { h =>
    ???
  }

  implicit val serviceListResponseEncoder: Encoder[ServiceListResponse] =
    Encoder.instance[ServiceListResponse] { resp =>
      Json.obj(
        "start"      -> Json.fromInt(resp.getStart()),
        "end"        -> Json.fromInt(resp.getEnd()),
        "totalCount" -> Json.fromInt(resp.getTotalCount()),
        "services" -> Json.fromValues(
          resp.getServices().map(serviceEncoder.apply)
        )
      )
    }

  implicit val serviceListResponseDecoder: Decoder[ServiceListResponse] =
    Decoder.instance[ServiceListResponse] { h =>
      for {
        start      <- h.get[Option[Int]]("start").map(_.getOrElse(0))
        ed         <- h.get[Option[Int]]("end").map(_.getOrElse(0))
        totalCount <- h.get[Option[Int]]("totalCount").map(_.getOrElse(0))
        services   <- h.get[Array[Service]]("services")
      } yield {
        var response = ServiceListResponse()
        response.setStart(start)
        response.setEnd(ed)
        response.setTotalCount(totalCount)
        response.setServices(services)
        response
      }
    }

  implicit val serviceConfigurationRequestEncoder: Encoder[ServiceConfigurationRequest] =
    Encoder.instance[ServiceConfigurationRequest] { req =>
      Json.obj(
        "pretty" -> Json.fromBoolean(req.isPretty()),
        "patch"  -> Json.fromString(req.getPatch())
      )
    }

  implicit val clientRegistrationRequestEncoder: Encoder[ClientRegistrationRequest] =
    Encoder.instance[ClientRegistrationRequest] { req =>
      Json.obj(
        "json"     -> Json.fromString(req.getJson()),
        "token"    -> Json.fromString(req.getToken()),
        "clientId" -> Json.fromString(req.getClientId())
      )
    }

  implicit val clientRegistrationResponseDecoder: Decoder[ClientRegistrationResponse] =
    Decoder.instance[ClientRegistrationResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        client          <- h.get[Client]("client")
      } yield {
        var response = ClientRegistrationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(ClientRegistrationResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setClient(client)
        response
      }
    }

  implicit val clientListResponseDecoder: Decoder[ClientListResponse] =
    Decoder.instance[ClientListResponse] { h =>
      for {
        start      <- h.get[Option[Int]]("start").map(_.getOrElse(0))
        ed         <- h.get[Option[Int]]("end").map(_.getOrElse(0))
        developer  <- h.get[Option[String]]("developer").map(_.orNull)
        totalCount <- h.get[Option[Int]]("totalCount").map(_.getOrElse(0))
        clients    <- h.get[Array[Client]]("clients")
      } yield {
        var response = new ClientListResponse()
        response.setStart(start)
        response.setEnd(ed)
        response.setDeveloper(developer)
        response.setTotalCount(totalCount)
        response.setClients(clients)
        response
      }
    }

  implicit val grantedScopesGetResponseDecoder: Decoder[GrantedScopesGetResponse] =
    Decoder.instance[GrantedScopesGetResponse] { h =>
      for {
        serviceApiKey <- h.get[Option[Long]]("serviceApiKey").map(_.getOrElse(0L))
        clientId      <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        subject       <- h.get[Option[String]]("subject").map(_.orNull)

        latestGrantedScopes <- h.get[Array[String]]("latestGrantedScopes")

        mergedGrantedScopes <- h.get[Array[String]]("mergedGrantedScopes")

        modifiedAt <- h.get[Option[Long]]("modifiedAt").map(_.getOrElse(0L))
      } yield {
        var response = GrantedScopesGetResponse()
        response.setServiceApiKey(serviceApiKey)
        response.setClientId(clientId)
        response.setSubject(subject)
        response.setLatestGrantedScopes(latestGrantedScopes)
        response.setMergedGrantedScopes(mergedGrantedScopes)
        response.setModifiedAt(modifiedAt)
        response
      }
    }

  implicit val clientAuthorizationGetListRequestEncoder
      : Encoder[ClientAuthorizationGetListRequest] =
    Encoder.instance[ClientAuthorizationGetListRequest] { req =>
      Json.obj(
        "subject"   -> Json.fromString(req.getSubject()),
        "developer" -> Json.fromString(req.getDeveloper()),
        "start"     -> Json.fromInt(req.getStart()),
        "end"       -> Json.fromInt(req.getEnd())
      )
    }

  implicit val authorizedClientListResponseDecoder: Decoder[AuthorizedClientListResponse] =
    Decoder.instance[AuthorizedClientListResponse] { h =>
      for {
        start      <- h.get[Option[Int]]("start").map(_.getOrElse(0))
        ed         <- h.get[Option[Int]]("end").map(_.getOrElse(0))
        developer  <- h.get[Option[String]]("developer").map(_.orNull)
        totalCount <- h.get[Option[Int]]("totalCount").map(_.getOrElse(0))
        clients    <- h.get[Array[Client]]("clients")
        subject    <- h.get[Option[String]]("subject").map(_.orNull)
      } yield {
        var response = AuthorizedClientListResponse()
        response.setStart(start)
        response.setEnd(ed)
        response.setDeveloper(developer)
        response.setTotalCount(totalCount)
        response.setClients(clients)
        response.setSubject(subject)

        response
      }
    }

  implicit val clientAuthorizationUpdateRequestEncoder: Encoder[ClientAuthorizationUpdateRequest] =
    Encoder.instance[ClientAuthorizationUpdateRequest] { req =>
      Json.obj(
        "subject" -> Json.fromString(req.getSubject()),
        "scopes"  -> Json.fromValues(req.getScopes().map(Json.fromString))
      )
    }

  implicit val clientSecretRefreshResponseDecoder: Decoder[ClientSecretRefreshResponse] =
    Decoder.instance[ClientSecretRefreshResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        newClientSecret <- h.get[Option[String]]("newClientSecret").map(_.orNull)
        oldClientSecret <- h.get[Option[String]]("oldClientSecret").map(_.orNull)
      } yield {
        var response = ClientSecretRefreshResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setNewClientSecret(newClientSecret)
        response.setOldClientSecret(oldClientSecret)
        response
      }
    }

  implicit val clientSecretUpdateResponseDecoder: Decoder[ClientSecretUpdateResponse] =
    Decoder.instance[ClientSecretUpdateResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        newClientSecret <- h.get[Option[String]]("newClientSecret").map(_.orNull)
        oldClientSecret <- h.get[Option[String]]("oldClientSecret").map(_.orNull)
      } yield {
        var response = ClientSecretUpdateResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setNewClientSecret(newClientSecret)
        response.setOldClientSecret(oldClientSecret)
        response
      }
    }

  implicit val joseVerifyRequestEncoder: Encoder[JoseVerifyRequest] =
    Encoder.instance[JoseVerifyRequest] { req =>
      Json.obj(
        "jose" -> Json.fromString(req.getJose()),
        "mandatoryClaims" -> Json.fromValues(
          req.getMandatoryClaims().map(Json.fromString)
        ),
        "clockSkew"        -> Json.fromInt(req.getClockSkew()),
        "clientIdentifier" -> Json.fromString(req.getClientIdentifier()),
        "signedByClient"   -> Json.fromBoolean(req.isSignedByClient())
      )
    }

  implicit val joseVerifyResponseDecoder: Decoder[JoseVerifyResponse] =
    Decoder.instance[JoseVerifyResponse] { h =>
      for {
        resultCode        <- h.get[String]("resultCode")
        resultMessage     <- h.get[String]("resultCode")
        valid             <- h.get[Option[Boolean]]("valid").map(_.getOrElse(false))
        signatureValid    <- h.get[Option[Boolean]]("signatureValid").map(_.getOrElse(false))
        missingClaims     <- h.get[Array[String]]("missingClaims")
        invalidClaims     <- h.get[Array[String]]("invalidClaims")
        errorDescriptions <- h.get[Array[String]]("errorDescriptions")
      } yield {
        var response = new JoseVerifyResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setValid(valid)
        response.setSignatureValid(signatureValid)
        response.setMissingClaims(missingClaims)
        response.setInvalidClaims(invalidClaims)
        response.setErrorDescriptions(errorDescriptions)
        response
      }
    }

  implicit val backchannelAuthenticationRequestEncoder: Encoder[BackchannelAuthenticationRequest] =
    Encoder.instance[BackchannelAuthenticationRequest] { req =>
      Json.obj(
        "parameters"        -> Json.fromString(req.getParameters()),
        "clientId"          -> Json.fromString(req.getClientId()),
        "clientSecret"      -> Json.fromString(req.getClientSecret()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "clientCertificatePath" -> Json.fromValues(
          req.getClientCertificatePath().map(Json.fromString)
        ),
        "oauthClientAttestation" -> Json.fromString(
          req.getOauthClientAttestation()
        ),
        "oauthClientAttestationPop" -> Json.fromString(
          req.getOauthClientAttestationPop()
        )
      )
    }

  implicit val backchannelAuthenticationResponseDecoder
      : Decoder[BackchannelAuthenticationResponse] =
    Decoder.instance[BackchannelAuthenticationResponse] { h =>
      for {
        resultCode         <- h.get[String]("resultCode")
        resultMessage      <- h.get[String]("resultCode")
        action             <- h.get[Option[String]]("action").map(_.orNull)
        responseContent    <- h.get[Option[String]]("responseContent").map(_.orNull)
        clientId           <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        clientIdAlias      <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed  <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId     <- h.get[URI]("clientEntityId")
        clientEntityIdUsed <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        clientName         <- h.get[Option[String]]("clientName").map(_.orNull)
        clientAuthMethod <-
          h.get[Option[String]]("clientAuthMethod")
            .map(clientAuthMethod => ClientAuthMethod.valueOf(clientAuthMethod.orNull))
        deliveryMode            <- h.get[Option[String]]("deliveryMode").map(_.orNull)
        scopes                  <- h.get[Array[String]]("scopes").map(_.map(Scope().setName(_)))
        dynamicScopes           <- h.get[Array[String]]("dynamicScopes")
        claimNames              <- h.get[Array[String]]("claimNames")
        clientNotificationToken <- h.get[Option[String]]("clientNotificationToken").map(_.orNull)
        acrs                    <- h.get[Array[String]]("acrs")
        hintType                <- h.get[Option[String]]("hintType").map(_.orNull)
        hint                    <- h.get[Option[String]]("hint").map(_.orNull)
        sub                     <- h.get[Option[String]]("sub").map(_.orNull)
        bindingMessage          <- h.get[Option[String]]("bindingMessage").map(_.orNull)
        userCode                <- h.get[Option[String]]("userCode").map(_.orNull)
        userCodeRequired        <- h.get[Option[Boolean]]("userCodeRequired").map(_.getOrElse(false))
        requestedExpiry         <- h.get[Option[Int]]("requestedExpiry").map(_.getOrElse(0))
        requestContext          <- h.get[Option[String]]("requestContext").map(_.orNull)
        resources               <- h.get[Array[URI]]("resources")
        authorizationDetails    <- h.get[AuthzDetails]("authorizationDetails")
        gmAction                <- h.get[Option[String]]("gmAction").map(_.orNull)
        grantId                 <- h.get[Option[String]]("grantId").map(_.orNull)
        grantSubject            <- h.get[Option[String]]("grantSubject").map(_.orNull)
        grant                   <- h.get[Grant]("grant")
        serviceAttributes       <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes        <- h.get[Array[Pair]]("clientAttributes")
        warnings                <- h.get[Array[String]]("warnings")
        ticket                  <- h.get[Option[String]]("ticket").map(_.orNull)
      } yield {
        var response = new BackchannelAuthenticationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          BackchannelAuthenticationResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response.setClientId(clientId)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed

        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setClientName(clientName)

        response.setClientAuthMethod(clientAuthMethod)

        response.setDeliveryMode(DeliveryMode.valueOf(deliveryMode))

        response.setScopes(scopes)

        // response.setDynamicScopes(dynamicScopes)

        response.setClaimNames(claimNames)

        response.setClientNotificationToken(clientNotificationToken)

        response.setAcrs(acrs)

        // response.setHintType(hintType)

        response.setHint(hint)

        response.setSub(sub)

        response.setBindingMessage(bindingMessage)

        response.setUserCode(userCode)

        response.setUserCodeRequired(userCodeRequired)

        response.setRequestedExpiry(requestedExpiry)

        response.setRequestContext(requestContext)

        response.setResources(resources)

        response.setAuthorizationDetails(authorizationDetails)

        // response.setGmAction(gmAction)

        response.setGrantId(grantId)

        response.setGrantSubject(grantSubject)

        response.setGrant(grant)

        response.setServiceAttributes(serviceAttributes)

        response.setClientAttributes(clientAttributes)

        response.setWarnings(warnings)

        response.setTicket(ticket)

        response

      }
    }

  implicit val backchannelAuthenticationIssueRequestEncoder
      : Encoder[BackchannelAuthenticationIssueRequest] =
    Encoder.instance[BackchannelAuthenticationIssueRequest] { req =>
      Json.obj(
        "ticket" -> Json.fromString(req.getTicket())
      )
    }

  implicit val backchannelAuthenticationIssueResponseDecoder
      : Decoder[BackchannelAuthenticationIssueResponse] =
    Decoder.instance[BackchannelAuthenticationIssueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        authReqId       <- h.get[Option[String]]("authReqId").map(_.orNull)
        expiresIn       <- h.get[Option[Int]]("expiresIn").map(_.getOrElse(0))
        interval        <- h.get[Option[Int]]("interval").map(_.getOrElse(0))
      } yield {
        var response = new BackchannelAuthenticationIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          BackchannelAuthenticationIssueResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response.setAuthReqId(authReqId)
        response.setExpiresIn(expiresIn)
        response.setInterval(interval)
        response
      }
    }

  implicit val backchannelAuthenticationFailRequestEncoder
      : Encoder[BackchannelAuthenticationFailRequest] =
    Encoder.instance[BackchannelAuthenticationFailRequest] { req =>
      Json.obj(
        "ticket"           -> Json.fromString(req.getTicket()),
        "reason"           -> Json.fromString(req.getReason().toString()),
        "errorDescription" -> Json.fromString(req.getErrorDescription()),
        "errorUri"         -> Json.fromString(req.getErrorUri().toString())
      )

    }

  implicit val backchannelAuthenticationFailResponseDecoder
      : Decoder[BackchannelAuthenticationFailResponse] =
    Decoder.instance[BackchannelAuthenticationFailResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new BackchannelAuthenticationFailResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          BackchannelAuthenticationFailResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val backchannelAuthenticationCompleteRequestEncoder
      : Encoder[BackchannelAuthenticationCompleteRequest] =
    Encoder.instance[BackchannelAuthenticationCompleteRequest] { req =>
      Json.obj(
        "ticket"   -> Json.fromString(req.getTicket()),
        "result"   -> Json.fromString(req.getResult().toString()),
        "subject"  -> Json.fromString(req.getSubject()),
        "sub"      -> Json.fromString(req.getSub()),
        "authTime" -> Json.fromLong(req.getAuthTime()),
        "acr"      -> Json.fromString(req.getAcr()),
        "claims"   -> Json.fromString(req.getClaims()),
        // "properties" -> Json.fromValues(req.getProperties().map(pairEncoder.apply)),
        "scopes"          -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "idtHeaderParams" -> Json.fromString(req.getIdtHeaderParams()),
        "consentedClaims" -> Json.fromValues(
          req.getConsentedClaims().map(Json.fromString)
        ),
        "jwtAtClaims"          -> Json.fromString(req.getJwtAtClaims()),
        "accessToken"          -> Json.fromString(req.getAccessToken()),
        "accessTokenDuration"  -> Json.fromLong(req.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(req.getRefreshTokenDuration()),
        "idTokenAudType"       -> Json.fromString(req.getIdTokenAudType()),
        "errorDescription"     -> Json.fromString(req.getErrorDescription()),
        "errorUri"             -> Json.fromString(req.getErrorUri().toString())
      )
    }

  implicit val backchannelAuthenticationCompleteResponseDecoder
      : Decoder[BackchannelAuthenticationCompleteResponse] =
    Decoder.instance[BackchannelAuthenticationCompleteResponse] { h =>
      for {
        resultCode                 <- h.get[String]("resultCode")
        resultMessage              <- h.get[String]("resultCode")
        action                     <- h.get[Option[String]]("action").map(_.orNull)
        responseContent            <- h.get[Option[String]]("responseContent").map(_.orNull)
        clientId                   <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        clientIdAlias              <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed          <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId             <- h.get[URI]("clientEntityId")
        clientEntityIdUsed         <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        clientName                 <- h.get[Option[String]]("clientName").map(_.orNull)
        deliveryMode               <- h.get[Option[String]]("deliveryMode").map(_.orNull)
        clientNotificationEndpoint <- h.get[URI]("clientNotificationEndpoint")
        clientNotificationToken    <- h.get[Option[String]]("clientNotificationToken").map(_.orNull)
        authReqId                  <- h.get[Option[String]]("authReqId").map(_.orNull)
        accessToken                <- h.get[Option[String]]("accessToken").map(_.orNull)
        refreshToken               <- h.get[Option[String]]("refreshToken").map(_.orNull)
        idToken                    <- h.get[Option[String]]("idToken").map(_.orNull)
        accessTokenDuration        <- h.get[Option[Long]]("accessTokenDuration").map(_.getOrElse(0L))
        refreshTokenDuration       <- h.get[Option[Long]]("refreshTokenDuration").map(_.getOrElse(0L))
        idTokenDuration            <- h.get[Option[Long]]("idTokenDuration").map(_.getOrElse(0L))
        jwtAccessToken             <- h.get[Option[String]]("jwtAccessToken").map(_.orNull)
        resources                  <- h.get[Array[URI]]("resources")
        authorizationDetails       <- h.get[AuthzDetails]("authorizationDetails")
        grantId                    <- h.get[Option[String]]("grantId").map(_.orNull)
        serviceAttributes          <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes           <- h.get[Array[Pair]]("clientAttributes")
      } yield {
        var response = new BackchannelAuthenticationCompleteResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          BackchannelAuthenticationCompleteResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response.setClientId(clientId)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed(clientIdAliasUsed)
        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setClientName(clientName)
        response.setDeliveryMode(DeliveryMode.valueOf(deliveryMode))
        response.setClientNotificationEndpoint(clientNotificationEndpoint)
        response.setClientNotificationToken(clientNotificationToken)
        response.setAuthReqId(authReqId)
        response.setAccessToken(accessToken)
        response.setRefreshToken(refreshToken)
        response.setIdToken

        response.setAccessTokenDuration(accessTokenDuration)

        response.setRefreshTokenDuration(refreshTokenDuration)

        response.setIdTokenDuration(idTokenDuration)

        response.setJwtAccessToken(jwtAccessToken)

        response.setResources(resources)

        response.setAuthorizationDetails(authorizationDetails)

        response.setGrantId(grantId)

        response.setServiceAttributes(serviceAttributes)

        response.setClientAttributes(clientAttributes)

        response

      }
    }

  implicit val deviceAuthorizationRequestEncoder: Encoder[DeviceAuthorizationRequest] =
    Encoder.instance[DeviceAuthorizationRequest] { req =>
      Json.obj(
        "parameters"        -> Json.fromString(req.getParameters()),
        "clientId"          -> Json.fromString(req.getClientId()),
        "clientSecret"      -> Json.fromString(req.getClientSecret()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "clientCertificatePath" -> Json.fromValues(
          req.getClientCertificatePath().map(Json.fromString)
        ),
        "oauthClientAttestation" -> Json.fromString(
          req.getOauthClientAttestation()
        ),
        "oauthClientAttestationPop" -> Json.fromString(
          req.getOauthClientAttestationPop()
        )
      )
    }

  implicit val deviceAuthorizationResponseDecoder: Decoder[DeviceAuthorizationResponse] =
    Decoder.instance[DeviceAuthorizationResponse] { h =>
      for {
        resultCode         <- h.get[String]("resultCode")
        resultMessage      <- h.get[String]("resultCode")
        action             <- h.get[Option[String]]("action").map(_.orNull)
        responseContent    <- h.get[Option[String]]("responseContent").map(_.orNull)
        clientId           <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        clientIdAlias      <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed  <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId     <- h.get[URI]("clientEntityId")
        clientEntityIdUsed <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        clientName         <- h.get[Option[String]]("clientName").map(_.orNull)
        clientAuthMethod <-
          h.get[Option[String]]("clientAuthMethod")
            .map(clientAuthMethod => ClientAuthMethod.valueOf(clientAuthMethod.orNull))
        scopes                  <- h.get[Array[String]]("scopes").map(_.map(Scope().setName(_)))
        dynamicScopes           <- h.get[Array[String]]("dynamicScopes")
        claimNames              <- h.get[Array[String]]("claimNames")
        acrs                    <- h.get[Array[String]]("acrs")
        deviceCode              <- h.get[Option[String]]("deviceCode").map(_.orNull)
        userCode                <- h.get[Option[String]]("userCode").map(_.orNull)
        verificationUri         <- h.get[URI]("verificationUri")
        verificationUriComplete <- h.get[URI]("verificationUriComplete")
        expiresIn               <- h.get[Option[Int]]("expiresIn").map(_.getOrElse(0))
        interval                <- h.get[Option[Int]]("interval").map(_.getOrElse(0))
        resources               <- h.get[Array[URI]]("resources")
        authorizationDetails    <- h.get[AuthzDetails]("authorizationDetails")
        gmAction                <- h.get[Option[String]]("gmAction").map(_.orNull)
        grantId                 <- h.get[Option[String]]("grantId").map(_.orNull)
        grantSubject            <- h.get[Option[String]]("grantSubject").map(_.orNull)
        grant                   <- h.get[Grant]("grant")
        serviceAttributes       <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes        <- h.get[Array[Pair]]("clientAttributes")
        warnings                <- h.get[Array[String]]("warnings")
      } yield {
        var response = new DeviceAuthorizationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(DeviceAuthorizationResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setClientId(clientId)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed(clientIdAliasUsed)
        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setClientName(clientName)
        response.setClientAuthMethod(clientAuthMethod)

        response.setScopes(scopes)

        // response.setDynamicScopes(dynamicScopes)

        response.setClaimNames(claimNames)

        response.setAcrs(acrs)

        response.setDeviceCode(deviceCode)

        response.setUserCode(userCode)

        response.setVerificationUri(verificationUri)

        response.setVerificationUriComplete(verificationUriComplete)

        response.setExpiresIn(expiresIn)

        response.setInterval(interval)

        response.setResources(resources)

        response.setAuthorizationDetails(authorizationDetails)

        // response.setGmAction(gmAction)

        response.setGrantId(grantId)

        response.setGrantSubject(grantSubject)

        response.setGrant(grant)

        response.setServiceAttributes(serviceAttributes)

        response.setClientAttributes(clientAttributes)

        response.setWarnings(warnings)

        response

      }
    }

  implicit val deviceCompleteRequestEncoder: Encoder[DeviceCompleteRequest] =
    Encoder.instance[DeviceCompleteRequest] { req =>
      Json.obj(
        "userCode" -> Json.fromString(req.getUserCode()),
        "result"   -> Json.fromString(req.getResult().toString()),
        "subject"  -> Json.fromString(req.getSubject()),
        "sub"      -> Json.fromString(req.getSub()),
        "authTime" -> Json.fromLong(req.getAuthTime()),
        "acr"      -> Json.fromString(req.getAcr()),
        "claims"   -> Json.fromString(req.getClaims()),
        // "properties" -> Json.fromValues(req.getProperties().map(pairEncoder.apply)),
        "scopes"          -> Json.fromValues(req.getScopes().map(Json.fromString)),
        "idtHeaderParams" -> Json.fromString(req.getIdtHeaderParams()),
        "consentedClaims" -> Json.fromValues(
          req.getConsentedClaims().map(Json.fromString)
        ),
        "jwtAtClaims"         -> Json.fromString(req.getJwtAtClaims()),
        "accessTokenDuration" -> Json.fromLong(req.getAccessTokenDuration()),
        "refreshTokenDuration" -> Json.fromLong(
          req.getRefreshTokenDuration()
        ),
        "idTokenAudType"   -> Json.fromString(req.getIdTokenAudType()),
        "errorDescription" -> Json.fromString(req.getErrorDescription()),
        "errorUri"         -> Json.fromString(req.getErrorUri().toString())
      )
    }

  implicit val deviceCompleteResponseDecoder: Decoder[DeviceCompleteResponse] =
    Decoder.instance[DeviceCompleteResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)

      } yield {
        var response = new DeviceCompleteResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(DeviceCompleteResponse.Action.valueOf(action))
        response

      }
    }

  implicit val deviceVerificationRequestEncoder: Encoder[DeviceVerificationRequest] =
    Encoder.instance[DeviceVerificationRequest] { req =>
      Json.obj(
        "userCode" -> Json.fromString(req.getUserCode())
      )
    }

  implicit val deviceVerificationResponseDecoder: Decoder[DeviceVerificationResponse] =
    Decoder.instance[DeviceVerificationResponse] { h =>
      for {
        resultCode           <- h.get[String]("resultCode")
        resultMessage        <- h.get[String]("resultCode")
        action               <- h.get[Option[String]]("action").map(_.orNull)
        responseContent      <- h.get[Option[String]]("responseContent").map(_.orNull)
        clientId             <- h.get[Option[Long]]("clientId").map(_.getOrElse(0L))
        clientIdAlias        <- h.get[Option[String]]("clientIdAlias").map(_.orNull)
        clientIdAliasUsed    <- h.get[Option[Boolean]]("clientIdAliasUsed").map(_.getOrElse(false))
        clientEntityId       <- h.get[URI]("clientEntityId")
        clientEntityIdUsed   <- h.get[Option[Boolean]]("clientEntityIdUsed").map(_.getOrElse(false))
        clientName           <- h.get[Option[String]]("clientName").map(_.orNull)
        scopes               <- h.get[Array[String]]("scopes").map(_.map(Scope().setName(_)))
        dynamicScopes        <- h.get[Array[String]]("dynamicScopes")
        claimNames           <- h.get[Array[String]]("claimNames")
        acrs                 <- h.get[Array[String]]("acrs")
        expiresAt            <- h.get[Option[Long]]("expiresAt").map(_.getOrElse(0L))
        resources            <- h.get[Array[URI]]("resources")
        authorizationDetails <- h.get[AuthzDetails]("authorizationDetails")
        gmAction             <- h.get[Option[String]]("gmAction").map(_.orNull)
        grantId              <- h.get[Option[String]]("grantId").map(_.orNull)
        grantSubject         <- h.get[Option[String]]("grantSubject").map(_.orNull)
        grant                <- h.get[Grant]("grant")
        serviceAttributes    <- h.get[Array[Pair]]("serviceAttributes")
        clientAttributes     <- h.get[Array[Pair]]("clientAttributes")
      } yield {
        var response = new DeviceVerificationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(DeviceVerificationResponse.Action.valueOf(action))
        // response.setResponseContent(responseContent)
        response.setClientId(clientId)
        response.setClientIdAlias(clientIdAlias)
        response.setClientIdAliasUsed(clientIdAliasUsed)
        response.setClientEntityId(clientEntityId)
        response.setClientEntityIdUsed(clientEntityIdUsed)
        response.setClientName(clientName)
        response.setScopes(scopes)
        // response.setDynamicScopes(dynamicScopes)
        response.setClaimNames(claimNames)
        response.setAcrs(acrs)
        response.setExpiresAt(expiresAt)
        response.setResources(resources)
        response.setAuthorizationDetails(authorizationDetails)
        response.setGmAction(GMAction.valueOf(gmAction))
        response.setGrantId(grantId)
        response.setGrantSubject(grantSubject)
        response

      }

    }

  implicit val pushedAuthReqRequestEncoder: Encoder[PushedAuthReqRequest] =
    Encoder.instance[PushedAuthReqRequest] { req =>
      Json.obj(
        "parameters"        -> Json.fromString(req.getParameters()),
        "clientId"          -> Json.fromString(req.getClientId()),
        "clientSecret"      -> Json.fromString(req.getClientSecret()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "clientCertificatePath" -> Json.fromValues(
          req.getClientCertificatePath().map(Json.fromString)
        ),
        "dpop"              -> Json.fromString(req.getDpop()),
        "htm"               -> Json.fromString(req.getHtm()),
        "htu"               -> Json.fromString(req.getHtu()),
        "dpopNonceRequired" -> Json.fromBoolean(req.isDpopNonceRequired()),
        "oauthClientAttestation" -> Json.fromString(
          req.getOauthClientAttestation()
        ),
        "oauthClientAttestationPop" -> Json.fromString(
          req.getOauthClientAttestationPop()
        )
      )
    }

  implicit val pushedAuthReqResponseDecoder: Decoder[PushedAuthReqResponse] =
    Decoder.instance[PushedAuthReqResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        clientAuthMethod <-
          h.get[Option[String]]("clientAuthMethod")
            .map(clientAuthMethod => ClientAuthMethod.valueOf(clientAuthMethod.orNull))
        requestUri <- h.get[URI]("requestUri")
        dpopNonce  <- h.get[Option[String]]("dpopNonce").map(_.orNull)
      } yield {
        var response = new PushedAuthReqResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(PushedAuthReqResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setClientAuthMethod(clientAuthMethod)
        response.setRequestUri(requestUri)
        response.setDpopNonce(dpopNonce)
        response
      }

    }

  implicit val hskCreateRequestEncoder: Encoder[HskCreateRequest] =
    Encoder.instance[HskCreateRequest] { req =>
      Json.obj(
        "kty"     -> Json.fromString(req.getKty()),
        "use"     -> Json.fromString(req.getUse()),
        "alg"     -> Json.fromString(req.getAlg()),
        "kid"     -> Json.fromString(req.getKid()),
        "hsmName" -> Json.fromString(req.getHsmName())
      )
    }

  implicit val hskResponseDecoder: Decoder[HskResponse] =
    Decoder.instance[HskResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)
        hsk           <- h.get[Hsk]("hsk")
      } yield {
        var response = new HskResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(HskResponse.Action.valueOf(action))
        response.setHsk(hsk)
        response
      }
    }

  implicit val hskListResponseDecoder: Decoder[HskListResponse] =
    Decoder.instance[HskListResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        hsks          <- h.get[Array[Hsk]]("hsks")
      } yield {
        var response = new HskListResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setHsks(hsks)
        response
      }
    }

  implicit val gMRequestEncoder: Encoder[GMRequest] =
    Encoder.instance[GMRequest] { req =>
      Json.obj(
        "gmAction"          -> Json.fromString(req.getGmAction().toString()),
        "grantId"           -> Json.fromString(req.getGrantId()),
        "accessToken"       -> Json.fromString(req.getAccessToken()),
        "clientCertificate" -> Json.fromString(req.getClientCertificate()),
        "dpop"              -> Json.fromString(req.getDpop()),
        "htm"               -> Json.fromString(req.getHtm()),
        "htu"               -> Json.fromString(req.getHtu()),
        "dpopNonceRequired" -> Json.fromBoolean(req.isDpopNonceRequired())
      )
    }

  implicit val gMResponseDecoder: Decoder[GMResponse] =
    Decoder.instance[GMResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        dpopNonce       <- h.get[Option[String]]("dpopNonce").map(_.orNull)
      } yield {
        var response = new GMResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(GMResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setDpopNonce(dpopNonce)
        response
      }
    }

  implicit val federationConfigurationRequestEncoder: Encoder[FederationConfigurationRequest] =
    Encoder.instance[FederationConfigurationRequest] { req =>
      Json.obj(
        "entityTypes" -> Json.fromValues(
          req.getEntityTypes().map(entityType => Json.fromString(entityType.toString()))
        )
      )

    }

  implicit val federationConfigurationResponseDecoder: Decoder[FederationConfigurationResponse] =
    Decoder.instance[FederationConfigurationResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new FederationConfigurationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          FederationConfigurationResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val federationRegistrationRequestEncoder: Encoder[FederationRegistrationRequest] =
    Encoder.instance[FederationRegistrationRequest] { req =>
      Json.obj(
        "entityConfiguration" -> Json.fromString(req.getEntityConfiguration()),
        "trustChain"          -> Json.fromString(req.getTrustChain())
      )
    }

  implicit val federationRegistrationResponseDecoder: Decoder[FederationRegistrationResponse] =
    Decoder.instance[FederationRegistrationResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        client          <- h.get[Client]("client")
      } yield {
        var response = new FederationRegistrationResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          FederationRegistrationResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response.setClient(client)
        response
      }
    }

  implicit val credentialIssuerMetadataRequestEncoder: Encoder[CredentialIssuerMetadataRequest] =
    Encoder.instance[CredentialIssuerMetadataRequest] { req =>
      Json.obj(
        "pretty" -> Json.fromBoolean(req.isPretty())
      )
    }

  implicit val credentialIssuerMetadataResponseDecoder: Decoder[CredentialIssuerMetadataResponse] =
    Decoder.instance[CredentialIssuerMetadataResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new CredentialIssuerMetadataResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          CredentialIssuerMetadataResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val credentialJwtIssuerMetadataRequestEncoder
      : Encoder[CredentialJwtIssuerMetadataRequest] =
    Encoder.instance[CredentialJwtIssuerMetadataRequest] { req =>
      Json.obj(
        "pretty" -> Json.fromBoolean(req.isPretty())
      )
    }

  implicit val credentialJwtIssuerMetadataResponseDecoder
      : Decoder[CredentialJwtIssuerMetadataResponse] =
    Decoder.instance[CredentialJwtIssuerMetadataResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new CredentialJwtIssuerMetadataResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          CredentialJwtIssuerMetadataResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response
      }

    }

  implicit val credentialIssuerJwksRequestEncoder: Encoder[CredentialIssuerJwksRequest] =
    Encoder.instance[CredentialIssuerJwksRequest] { req =>
      Json.obj(
        "pretty" -> Json.fromBoolean(req.isPretty())
      )
    }

  implicit val credentialIssuerJwksResponseDecoder: Decoder[CredentialIssuerJwksResponse] =
    Decoder.instance[CredentialIssuerJwksResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new CredentialIssuerJwksResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialIssuerJwksResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }
    }

  implicit val credentialOfferCreateRequestEncoder: Encoder[CredentialOfferCreateRequest] =
    Encoder.instance[CredentialOfferCreateRequest] { req =>
      Json.obj(
        "credentialConfigurationIds" -> Json.fromValues(
          req.getCredentialConfigurationIds().map(Json.fromString)
        ),
        "authorizationCodeGrantIncluded" -> Json.fromBoolean(
          req.isAuthorizationCodeGrantIncluded()
        ),
        "issuerStateIncluded" -> Json.fromBoolean(req.isIssuerStateIncluded()),
        "preAuthorizedCodeGrantIncluded" -> Json.fromBoolean(
          req.isPreAuthorizedCodeGrantIncluded()
        ),
        "subject"  -> Json.fromString(req.getSubject()),
        "duration" -> Json.fromLong(req.getDuration()),
        "context"  -> Json.fromString(req.getContext()),
        // "properties" -> Json.fromValues(req.getProperties().map(pairEncoder.apply)),
        "jwtAtClaims"       -> Json.fromString(req.getJwtAtClaims()),
        "authTime"          -> Json.fromLong(req.getAuthTime()),
        "acr"               -> Json.fromString(req.getAcr()),
        "txCode"            -> Json.fromString(req.getTxCode()),
        "txCodeInputMode"   -> Json.fromString(req.getTxCodeInputMode()),
        "txCodeDescription" -> Json.fromString(req.getTxCodeDescription())
      )
    }

  implicit val credentialOfferCreateResponseDecoder: Decoder[CredentialOfferCreateResponse] =
    Decoder.instance[CredentialOfferCreateResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)
        info          <- h.get[Option[CredentialOfferInfo]]("info").map(_.orNull)
      } yield {
        var response = new CredentialOfferCreateResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialOfferCreateResponse.Action.valueOf(action))
        response.setInfo(info)
        response
      }
    }

  implicit val credentialOfferInfoRequestEncoder: Encoder[CredentialOfferInfoRequest] =
    Encoder.instance[CredentialOfferInfoRequest] { req =>
      Json.obj(
        "identifier" -> Json.fromString(req.getIdentifier())
      )

    }

  implicit val credentialOfferInfoResponseDecoder: Decoder[CredentialOfferInfoResponse] =
    Decoder.instance[CredentialOfferInfoResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)
        info          <- h.get[Option[CredentialOfferInfo]]("info").map(_.orNull)
      } yield {
        var response = new CredentialOfferInfoResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialOfferInfoResponse.Action.valueOf(action))
        response.setInfo(info)
        response
      }
    }

  implicit val credentialSingleParseRequestEncoder: Encoder[CredentialSingleParseRequest] =
    Encoder.instance[CredentialSingleParseRequest] { req =>
      Json.obj(
        "accessToken"    -> Json.fromString(req.getAccessToken()),
        "requestContent" -> Json.fromString(req.getRequestContent())
      )

    }

  implicit val credentialSingleParseResponseDecoder: Decoder[CredentialSingleParseResponse] =
    Decoder.instance[CredentialSingleParseResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        info            <- h.get[Option[CredentialRequestInfo]]("info").map(_.orNull)
      } yield {
        var response = new CredentialSingleParseResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialSingleParseResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setInfo(info)
        response
      }
    }

  implicit val credentialSingleIssueRequestEncoder: Encoder[CredentialSingleIssueRequest] =
    Encoder.instance[CredentialSingleIssueRequest] { req =>
      Json.obj(
        "accessToken" -> Json.fromString(req.getAccessToken()),
        "order"       -> Json.fromString(req.getOrder().toString)
      )
    }

  implicit val credentialSingleIssueResponseDecoder: Decoder[CredentialSingleIssueResponse] =
    Decoder.instance[CredentialSingleIssueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        transactionId   <- h.get[Option[String]]("transactionId").map(_.orNull)
      } yield {
        var response = new CredentialSingleIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialSingleIssueResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setTransactionId(transactionId)
        response
      }
    }

  implicit val credentialBatchParseRequestEncoder: Encoder[CredentialBatchParseRequest] =
    Encoder.instance[CredentialBatchParseRequest] { req =>
      Json.obj(
        "accessToken"    -> Json.fromString(req.getAccessToken()),
        "requestContent" -> Json.fromString(req.getRequestContent())
      )
    }

  implicit val credentialBatchParseResponseDecoder: Decoder[CredentialBatchParseResponse] =
    Decoder.instance[CredentialBatchParseResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        info            <- h.get[Option[Array[CredentialRequestInfo]]]("info").map(_.orNull)
      } yield {
        var response = new CredentialBatchParseResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialBatchParseResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setInfo(info)
        response
      }
    }

  implicit val credentialBatchIssueRequestEncoder: Encoder[CredentialBatchIssueRequest] =
    Encoder.instance[CredentialBatchIssueRequest] { req =>
      Json.obj(
        "accessToken" -> Json.fromString(req.getAccessToken()),
        "orders" -> Json.fromValues(
          req.getOrders().map(order => Json.fromString(order.toString))
        )
      )
    }

  implicit val credentialBatchIssueResponseDecoder: Decoder[CredentialBatchIssueResponse] =
    Decoder.instance[CredentialBatchIssueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new CredentialBatchIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(CredentialBatchIssueResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response
      }

    }

  implicit val credentialDeferredParseRequestEncoder: Encoder[CredentialDeferredParseRequest] =
    Encoder.instance[CredentialDeferredParseRequest] { req =>
      Json.obj(
        "accessToken"    -> Json.fromString(req.getAccessToken()),
        "requestContent" -> Json.fromString(req.getRequestContent())
      )
    }

  implicit val credentialDeferredParseResponseDecoder: Decoder[CredentialDeferredParseResponse] =
    Decoder.instance[CredentialDeferredParseResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        info            <- h.get[Option[CredentialRequestInfo]]("info").map(_.orNull)
      } yield {
        var response = new CredentialDeferredParseResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          CredentialDeferredParseResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response.setInfo(info)
        response
      }

    }

  implicit val credentialDeferredIssueRequestEncoder: Encoder[CredentialDeferredIssueRequest] =
    Encoder.instance[CredentialDeferredIssueRequest] { req =>
      Json.obj(
        "order" -> Json.fromString(req.getOrder().toString)
      )
    }

  implicit val credentialDeferredIssueResponseDecoder: Decoder[CredentialDeferredIssueResponse] =
    Decoder.instance[CredentialDeferredIssueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
      } yield {
        var response = new CredentialDeferredIssueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          CredentialDeferredIssueResponse.Action.valueOf(action)
        )
        response.setResponseContent(responseContent)
        response
      }

    }

  implicit val iDTokenReissueRequestEncoder: Encoder[IDTokenReissueRequest] =
    Encoder.instance[IDTokenReissueRequest] { req =>
      Json.obj(
        "accessToken"     -> Json.fromString(req.getAccessToken()),
        "refreshToken"    -> Json.fromString(req.getRefreshToken()),
        "sub"             -> Json.fromString(req.getSub()),
        "claims"          -> Json.fromString(req.getClaims()),
        "idtHeaderParams" -> Json.fromString(req.getIdtHeaderParams()),
        "idTokenAudType"  -> Json.fromString(req.getIdTokenAudType())
      )
    }

  implicit val iDTokenReissueResponseDecoder: Decoder[IDTokenReissueResponse] =
    Decoder.instance[IDTokenReissueResponse] { h =>
      for {
        resultCode      <- h.get[String]("resultCode")
        resultMessage   <- h.get[String]("resultCode")
        action          <- h.get[Option[String]]("action").map(_.orNull)
        responseContent <- h.get[Option[String]]("responseContent").map(_.orNull)
        idToken         <- h.get[Option[String]]("idToken").map(_.orNull)
      } yield {
        var response = new IDTokenReissueResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(IDTokenReissueResponse.Action.valueOf(action))
        response.setResponseContent(responseContent)
        response.setIdToken(idToken)
        response
      }
    }

  implicit val authorizationTicketInfoResponseDecoder: Decoder[AuthorizationTicketInfoResponse] =
    Decoder.instance[AuthorizationTicketInfoResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)
        info          <- h.get[Option[String]]("info").map(_.orNull)
      } yield {
        var response = new AuthorizationTicketInfoResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          AuthorizationTicketInfoResponse.Action.valueOf(action)
        )
        response.setInfo(new AuthorizationTicketInfo().setContext(info))
        response
      }
    }

  implicit val authorizationTicketInfoRequestEncoder: Encoder[AuthorizationTicketInfoRequest] =
    Encoder.instance[AuthorizationTicketInfoRequest] { req =>
      Json.obj(
        "ticket" -> Json.fromString(req.getTicket())
      )
    }

  implicit val authorizationTicketUpdateRequestEncoder: Encoder[AuthorizationTicketUpdateRequest] =
    Encoder.instance[AuthorizationTicketUpdateRequest] { req =>
      Json.obj(
        "ticket" -> Json.fromString(req.getTicket()),
        "info"   -> Json.fromString(req.getInfo().getContext())
      )
    }

  implicit val authorizationTicketUpdateResponseDecoder
      : Decoder[AuthorizationTicketUpdateResponse] =
    Decoder.instance[AuthorizationTicketUpdateResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        action        <- h.get[Option[String]]("action").map(_.orNull)
        info          <- h.get[Option[String]]("info").map(_.orNull)
      } yield {
        var response = AuthorizationTicketUpdateResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setAction(
          AuthorizationTicketUpdateResponse.Action.valueOf(action)
        )
        response.setInfo(new AuthorizationTicketInfo().setContext(info))
        response
      }
    }

  implicit val tokenCreateBatchResponseDecoder: Decoder[TokenCreateBatchResponse] =
    Decoder.instance[TokenCreateBatchResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        requestId     <- h.get[Option[String]]("requestId").map(_.orNull)
      } yield {
        var response = new TokenCreateBatchResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setRequestId(requestId)
        response
      }
    }

  implicit val tokenCreateBatchStatusResponseDecoder: Decoder[TokenCreateBatchStatusResponse] =
    Decoder.instance[TokenCreateBatchStatusResponse] { h =>
      for {
        resultCode    <- h.get[String]("resultCode")
        resultMessage <- h.get[String]("resultCode")
        status        <- h.get[Option[TokenBatchStatus]]("status")

      } yield {
        var response = new TokenCreateBatchStatusResponse()
        response.setResultCode(resultCode)
        response.setResultMessage(resultMessage)
        response.setStatus(status.orNull)

        response
      }
    }

  implicit def jsonEntityDecoder[F[_]: Async, A](using
      Decoder[A]
  ): EntityDecoder[F, A] = {
    EntityDecoder.decodeBy[F, A](MediaType.application.json) { msg =>
      DecodeResult[F, A](
        msg
          .as[String]
          .flatMap { str =>
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

  // implicit def clientApiResonseDecoder[F[_]: Concurrent]
  //     : EntityDecoder[F, Either[ApiResponse, Client]] =
  //   EntityDecoder.decodeBy[F, Either[ApiResponse, Client]](
  //     MediaType.application.json
  //   ) { msg =>
  //     clientEntityDecoder
  //       .decode(msg, strict = false)
  //       .map(_.asRight[ApiResponse])
  //       .handleErrorWith(_ =>
  //         apiResponseEntityDecoder
  //           .decode(msg, strict = false)
  //           .map(_.asLeft[Client])
  //       )
  //   }

  // implicit def clientApiResonseDecoder3[F[_]: Concurrent]
  //     : EntityDecoder[F, Client | ApiResponse] =
  //   EntityDecoder.decodeBy[F, Client | ApiResponse](
  //     MediaType.application.json
  //   ) { msg =>
  //     clientEntityDecoder
  //       .decode(msg, strict = false)
  //       .map(_.asInstanceOf[Client | ApiResponse])
  //       .handleErrorWith(_ =>
  //         apiResponseEntityDecoder
  //           .decode(msg, strict = false)
  //           .map(_.asInstanceOf[Client | ApiResponse])
  //       )
  //   }

}
