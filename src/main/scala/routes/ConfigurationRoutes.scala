package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import services.AuthleteService

final case class ConfigurationRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {

  val routes = HttpRoutes.of[F] {
    /**
      * OpenID Provider configuration endpoint.
      */
    case GET -> Root / ".well-known/openid-configuration" =>
      // authleteService.getService().map(_)
      Ok("Hello, World!")
  }

}
