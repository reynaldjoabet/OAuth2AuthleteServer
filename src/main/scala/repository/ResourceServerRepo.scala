package repository

trait ResourceServerRepo[F[_]] {
  def getResourceServer(id: String, secret: String): F[Unit]
}
