package org.sba_research

import com.typesafe.config.ConfigFactory

case class Config(adt: (String, String), dfd: (String, String), outputPath: String)

object Config {

  def apply(): Config = {
    val conf = ConfigFactory.load()

    val adtNs = conf.getString("adt.ns")
    val adtFileName = conf.getString("adt.fileName")

    val dfdNs = conf.getString("dfd.ns")
    val dfdFileName = conf.getString("dfd.fileName")

    val outputPath = conf.getString("outputPath")

    this ((adtFileName, adtNs), (dfdFileName, dfdNs), outputPath)
  }

}