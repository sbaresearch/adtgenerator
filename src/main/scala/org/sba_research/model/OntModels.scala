package org.sba_research.model

import org.apache.jena.ontology.{OntModel, OntModelSpec}
import org.apache.jena.rdf.model.ModelFactory
import org.sba_research.Config

case class OntModels(adt: OntModel, dfd: OntModel)

object OntModels {

  def apply(config: Config): OntModels = {

    def createModel(fileName: String) = {
      val m = ModelFactory.createOntologyModel(OntModelSpec.OWL_LITE_MEM)
      m.read(getClass.getResourceAsStream(s"/$fileName"), "adt")
      m
    }

    this (createModel(config.adt._1), createModel(config.dfd._1))
  }
}