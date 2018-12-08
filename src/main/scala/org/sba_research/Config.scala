package org.sba_research

import com.typesafe.config.ConfigFactory

case class Config(adt: (String, String), dfd: (String, String), outputPath: String)

object Config {

  def apply(): Config = {
    val conf = ConfigFactory.load()

    val adtNs = conf.getString("adt.ns")
    val adtFileName = conf.getString("adt.fileName")
    val adtPath = getClass.getResource(s"/$adtFileName").toString

    val dfdNs = conf.getString("dfd.ns")
    val dfdFileName = conf.getString("dfd.fileName")
    val dfdPath = getClass.getResource(s"/$dfdFileName").toString

    val outputPath = conf.getString("outputPath")

    this ((adtPath, adtNs), (dfdPath, dfdNs), outputPath)
  }

}