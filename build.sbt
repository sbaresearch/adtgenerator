name := "software-testing-adtrees-generator"

version := "0.1"

scalaVersion := "2.12.7"

val jenaVersion = "3.9.0"

libraryDependencies ++= Seq(
  "org.apache.jena" % "jena-core" % jenaVersion,
  "org.apache.jena" % "jena-arq" % jenaVersion,
  "com.typesafe" % "config" % "1.3.2",
  "org.slf4j" % "slf4j-simple" % "1.6.4",
  "org.scala-lang.modules" %% "scala-xml" % "1.1.1",
  "org.apache.commons" % "commons-lang3" % "3.8.1"
)
