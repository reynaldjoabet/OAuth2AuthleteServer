package utils

//
object AccessTokenValidator {
  // Validate the access token.

  def validate[F[_]](accessToken: String, requiredScopes: Set[String], requestedSubject: String) = 9
}
