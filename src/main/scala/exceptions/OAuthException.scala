package exceptions

import scala.util.control.NoStackTrace

enum OAuthException(message: String) extends RuntimeException(message) with NoStackTrace {

  case DpopValidationError(message: String)         extends OAuthException(message)
  case MissingAccessTokenException(message: String) extends OAuthException(message) // missing dpop header

  case InsufficientScope(scopes: String, message: String) extends OAuthException(message)

}
