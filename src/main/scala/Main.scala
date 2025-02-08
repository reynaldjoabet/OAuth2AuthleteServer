import cats.effect.ExitCode
import cats.effect.IO
import fs2.*
import fs2.io.file.Files
import fs2.io.file.Path

object Main extends App {

  println("Hello, World!")

  val EntrySplitter = "---------\n"

  type Entry = String

  val parseEntry: String => Option[Entry] = x=>None //???

  def run(args: List[String]) =
    Files[IO]
      .readAll(Path("/"))
      .through(text.utf8.decode)
      .repartition(s => fs2.Chunk.array(s.split(EntrySplitter)))
      .map(parseEntry)
      .map {
        case None        => fs2.Chunk.empty
        case Some(value) => fs2.Chunk(value)
      }
      .flatMap(fs2.Stream.chunk)
      // Now you can boil or bake it.
      .compile.drain >> IO.pure(
      ExitCode.Success
    )

  Files[IO]
      .readAll(Path("/"))
      .through(text.utf8.decode)
      .split(_.contains(EntrySplitter))
      .map(_.toList.mkString)
      .map(parseEntry)
      .collect { case Some(entry) => entry }

       
  // Files[IO]
  //      .readAll(Path(args(0)))
  //      .through(text.utf8.decode)
  //      .through(fs2.text.(EntrySplitter)) // Correct way to split efficiently
  //      .map(parseEntry)
  //      .unNone // Removes None values

   Files[IO]
        .readAll(Path("/"))
        .through(text.utf8.decode)
        .repartition(s => fs2.Chunk.array(s.split(EntrySplitter)))
        .map(parseEntry)
        .unNone    

        Stream("Hel", "l", "o Wor", "ld").repartition(s => Chunk.array(s.split(" "))).toList//List[String] = List(Hello, World)
}
