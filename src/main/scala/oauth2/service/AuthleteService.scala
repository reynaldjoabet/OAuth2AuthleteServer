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
import sttp.client4.Response

trait AuthleteService[F[_]] {

  /** /api/client/get endpoint
    *
    * [[https://docs.authlete.com/#client-get-api]]
    */
  def clientGet(clientId: String): F[Response[Either[ApiResponse, Client]]]

  /** /api/auth/authorization endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-api]]
    */
  def authorization(
      request: AuthorizationRequest
  ): F[Response[Either[ApiResponse, AuthorizationResponse]]]

  /** /api/auth/authorization/issue endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-issue-api]]
    */
  def authorizationIssue(
      request: AuthorizationIssueRequest
  ): F[Response[Either[ApiResponse, AuthorizationIssueResponse]]]

  /** /api/auth/authorization/fail endpoint
    *
    * [[https://docs.authlete.com/#auth-authorization-fail-api]]
    */
  def authorizationFail(
      request: AuthorizationFailRequest
  ): F[Response[Either[ApiResponse, AuthorizationFailResponse]]]

  /** /api/auth/token endpoint
    *
    * [[https://docs.authlete.com/#token-endpoint]]
    */
  def token(
      request: TokenRequest
  ): F[Response[Either[ApiResponse, TokenResponse]]]

  /** /api/auth/introspection endpoint
    *
    * [[https://docs.authlete.com/#introspection-endpoint]]
    */
  def introspection(
      request: IntrospectionRequest
  ): F[Response[Either[ApiResponse, IntrospectionResponse]]]

  /** /api/auth/revocation endpoint
    *
    * [[https://docs.authlete.com/#revocation-endpoint]]
    */
  def revocation(
      request: RevocationRequest
  ): F[Response[Either[ApiResponse, RevocationResponse]]]
}
