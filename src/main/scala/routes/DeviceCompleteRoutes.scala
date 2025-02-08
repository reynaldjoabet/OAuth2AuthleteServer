package routes

import cats.effect.kernel.Async
import cats.syntax.all.*

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import services.AuthleteService

final case class DeviceCompleteRoutes[F[_]: Async](authleteService: AuthleteService[F])
    extends Http4sDsl[F] {}
