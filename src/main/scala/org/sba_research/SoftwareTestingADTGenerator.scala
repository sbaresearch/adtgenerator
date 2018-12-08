package org.sba_research

import org.sba_research.model._


object SoftwareTestingADTGenerator {

  def main(args: Array[String]): Unit = {

    val config = Config()

    val ontModels = OntModels(config)

    //val goalsClass = ontModels.adt.getOntClass(config.adt._2 + "#Goal")
    //val goals = goalsClass.listInstances().toList
    //println(goals)
    //val goal = goals.get(3)

    //val adtTree = ADTOntModelConverter.getADT(config, ontModels.adt, goal, Map.empty[String, Int])

    val adt2 = ADTOntModelConverter.getADTBy(config, ontModels)
    adt2.map(t => ADTXMLMarshaller.execute(config.outputPath, t))

    // Sabotage ADT
    //ADTOntModelConverter.getSabotageADT(config, ontModels).map(t => ADTXMLMarshaller.execute(config.outputPath, t))

  }


}