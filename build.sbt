ThisBuild / scalaVersion := "3.3.3"

ThisBuild / name    := "OAuth2AuthleteServer"
ThisBuild / version := "1.0"

ThisBuild / scalacOptions ++= Seq(
  "-no-indent",
  "-deprecation", // Warns about deprecated APIs
  "-feature",     // Warns about advanced language features
  "-unchecked"
  // "-Wunused:imports",
  //   "-Wunused:privates",
  //   "-Wunused:locals",
  //   "-Wunused:explicits",
  //   "-Wunused:implicits",
  //   "-Wunused:params",
  //   "-Wvalue-discard",
  // "-language:strictEquality"
)

ThisBuild / bspEnabled := true

ThisBuild / semanticdbEnabled := true

ThisBuild / cancelable := true

ThisBuild / usePipelining := true

lazy val http4sVersion   = "0.23.28"
lazy val flywayVersion   = "10.22.0"
lazy val postgresVersion = "42.7.4"
lazy val catsVersion     = "2.11.0"
lazy val logbackVersion  = "1.5.8"
lazy val circeVersion    = "0.14.10"
lazy val skunkVersion    = "1.1.0-M3"
val catsEffectVersion    = "3.5.4"
val doobieVersion        = "1.1.0-M3"
val fs2Version           = "3.11.0"
val refinedVersion       = "0.11.2"
val circeRefinedVersion  = "0.14.9"
val pureconfigVersion    = "0.17.8"

def circe(artifact: String): ModuleID =
  "io.circe" %% s"circe-$artifact" % circeVersion

def http4s(artifact: String): ModuleID =
  "org.http4s" %% s"http4s-$artifact" % http4sVersion

def pureconfig(artifact: String) =
  "com.github.pureconfig" %% s"pureconfig-$artifact" % pureconfigVersion

// https://mvnrepository.com/artifact/com.github.jwt-scala/jwt-core
def jwtScala(artifact: String) =
  "com.github.jwt-scala" %% s"jwt-$artifact" % "10.0.1"

val cats               = "org.typelevel" %% "cats-core"     % "2.8.0"
val circeRefined       = "io.circe"      %% "circe-refined" % circeRefinedVersion
val refined            = "eu.timepit"    %% "refined"       % refinedVersion
val refinedCats        = "eu.timepit"    %% "refined-cats"  % refinedVersion
val circeGenericExtras = circe("generic-extras")
val circeCore          = circe("core")
val circeGeneric       = circe("generic")
val circeParser        = circe("parser")
val circeLiteral       = circe("literal")
val circeJawn          = circe("jawn")
val catsEffect         = "org.typelevel" %% "cats-effect"   % catsEffectVersion
val fs2                = "co.fs2"        %% "fs2-core"      % fs2Version
val http4sDsl          = http4s("dsl")
val http4sServer       = http4s("ember-server")
val http4sClient       = http4s("ember-client")
val http4sCirce        = http4s("circe")
val auth0Jwt           = "com.auth0"      % "java-jwt"      % "4.4.0"
val auth0Jwks          = "com.auth0"      % "jwks-rsa"      % "0.22.1"

val postgres       = "org.postgresql" % "postgresql"      % postgresVersion
val logback        = "ch.qos.logback" % "logback-classic" % logbackVersion
val skunk          = "org.tpolecat"  %% "skunk-core"      % skunkVersion
val pureconfigCore = pureconfig("core")
val pureconfigCats = pureconfig("cats")
val jwtScalaCore   = jwtScala("core")
val jwtScalaCirce  = jwtScala("circe")

// https://mvnrepository.com/artifact/com.authlete/authlete-java-common
val authlete = "com.authlete" % "authlete-java-common" % "4.16"
// https://mvnrepository.com/artifact/com.softwaremill.sttp.client4/core
val sttpCore = "com.softwaremill.sttp.client4" %% "core" % "4.0.0-M20"

// https://mvnrepository.com/artifact/com.nimbusds/nimbus-jose-jwt
val nimbusJoseJwt = "com.nimbusds" % "nimbus-jose-jwt" % "9.47"

// https://mvnrepository.com/artifact/org.bouncycastle/bcprov-jdk18on
//Bouncy Castle Provider
libraryDependencies += "org.bouncycastle" % "bcprov-jdk18on" % "1.79"

val root = project
  .in(file("."))
  .settings(
    libraryDependencies ++= Seq(
      cats,
      catsEffect,
      circeCore,
      circeGeneric,
      // circeGenericExtras,
      circeLiteral,
      circeParser,
      circeJawn,
      circeRefined,
      circeRefined,
      fs2,
      http4sDsl,
      http4sServer,
      http4sClient,
      http4sCirce,
      auth0Jwt,
      auth0Jwks,
      postgres,
      logback,
      skunk,
      pureconfigCore,
      pureconfigCats,
      jwtScalaCore,
      jwtScalaCirce,
      authlete,
      refined,
      refinedCats,
      sttpCore,
      nimbusJoseJwt
    )
  )
