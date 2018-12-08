package org.sba_research

import org.apache.jena.ontology.{Individual, OntModel, OntResource}
import org.apache.jena.query.{QueryExecutionFactory, QueryFactory}
import org.sba_research.model._

import scala.annotation.tailrec
import scala.collection.JavaConversions._

object ADTOntModelConverter {

  sealed trait ADTOntModelConverterError

  case object GoalSubTreeError extends ADTOntModelConverterError

  case object SubTreeError extends ADTOntModelConverterError

  case object ADTNodesError extends ADTOntModelConverterError

  case object NotAConnectorOwlResource extends ADTOntModelConverterError

  private def getFlowsFromProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#flowsFrom")

  private def getFlowsToProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#flowsTo")

  private def getFlowsProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#flows")

  private def getConnectedToProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#connectedTo")

  private def getHasTypeProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#hasType")

  private def getHasTargetProperty(ns: String, ontModel: OntModel) = getResourceProperty(ns, ontModel, "#hasTarget")

  private def getGoalClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#Goal")

  private def getOrConnectorClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#OrConnector")

  private def getAndConnectorClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#AndConnector")

  private def getAttackNodeClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#AttackNode")

  private def getDefenseNodeClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#DefenseNode")

  private def getProcessClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#Process")

  private def getDataStoreClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#DataStore")

  private def getDataFlowClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#DataFlow")

  private def getExternalEntityClass(ns: String, ontModel: OntModel) = getResourceClass(ns, ontModel, "#ExternalEntity")

  private def getResourceClass(ns: String, ontModel: OntModel, label: String) = ontModel.getOntClass(ns + label)

  private def getResourceProperty(ns: String, ontModel: OntModel, label: String) = ontModel.getOntProperty(ns + label)

  def getADTBy(config: Config, ontModels: OntModels): Either[ADTOntModelConverterError, Goal] = {
    // Get all DFD elements that use a given asset
    val qGetDfdElementsByAssetString =
      """
        |PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
        |PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        |PREFIX owl: <http://www.w3.org/2002/07/owl#>
        |PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        |PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        |SELECT ?asset ?individual ?id
        |	WHERE {
        |		?asset rdf:type ?assetType.
        |		?assetType rdfs:subClassOf* ns:Asset.
        |		?asset ns:usedBy ?individual.
        |		?individual ns:id ?id.
        |		?asset rdfs:label "Source Code"@en.
        |	}
        |ORDER BY ?asset
      """.stripMargin

    val qGetDfdElementsByAsset = QueryFactory.create(qGetDfdElementsByAssetString)
    val qGetDfdElementsByAssetExec = QueryExecutionFactory.create(qGetDfdElementsByAsset, ontModels.dfd)
    val getDfdElementsByAsset = qGetDfdElementsByAssetExec.execSelect().toList
    getDfdElementsByAsset foreach println

    case class InvolvedDFDElement(id: String, label: String, targetElement: String)

    val classes = List(
      getDataFlowClass(config.dfd._2, ontModels.dfd),
      getExternalEntityClass(config.dfd._2, ontModels.dfd),
      getProcessClass(config.dfd._2, ontModels.dfd),
      getDataStoreClass(config.dfd._2, ontModels.dfd)
    )

    val involvedDfdElements: List[InvolvedDFDElement] = getDfdElementsByAsset.flatMap { r =>
      val usedByIndv = r.getResource("individual")
      val usedByIndvId = r.getLiteral("?id")
      val indv = ontModels.dfd.getOntResource(usedByIndv).asIndividual()
      val cls = classes.find(c => indv.hasOntClass(c))
      cls match {
        case Some(dataFlowClass: OntResource) if dataFlowClass == getDataFlowClass(config.dfd._2, ontModels.dfd) =>
          val stmts = indv.listProperties().toList.filter { s =>
            s.getPredicate == getFlowsProperty(config.dfd._2, ontModels.dfd) ||
              s.getPredicate == getFlowsToProperty(config.dfd._2, ontModels.dfd) ||
              s.getPredicate == getFlowsFromProperty(config.dfd._2, ontModels.dfd)
          }
          val flowList = stmts.map { s =>
            val verb = OntModelUtils.removeNamespace(s.getPredicate.toString)
            val flowTarget = ontModels.dfd.getIndividual(s.getObject.toString).getLabel("en")
            s"$verb $flowTarget"
          }
          val label = s"${indv.getLabel("en")} [${flowList.mkString(" and ")}]"
          Some(InvolvedDFDElement(usedByIndvId.getString, label, OntModelUtils.removeNamespace(dataFlowClass.toString)))
        case Some(c) => Some(InvolvedDFDElement(usedByIndvId.getString, indv.getLabel("en"), OntModelUtils.removeNamespace(c.toString)))
        case _ => None
      }
    }

    println(involvedDfdElements)

    val targetList = involvedDfdElements.map(e => s"ns:${e.targetElement}").distinct.mkString(", ")

    val threatType = "InformationDisclosure"

    // Query all goals that have as target `targetElement` and as `hasType` STRIDE threat

    val qThreatTreeGoalsString =
      s"""
         |PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/ADT#>
         |PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
         |PREFIX owl: <http://www.w3.org/2002/07/owl#>
         |PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
         |PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
         |SELECT ?goal ?hasTarget
         |	WHERE {
         |		?goal rdf:type ?goalType.
         |		?goalType rdfs:subClassOf* ns:Goal.
         |		?goal ns:hasTarget ?hasTarget.
         |		?goal ns:hasType ?hasType.
         |		FILTER(?hasTarget IN ($targetList) && ?hasType = ns:$threatType)
         |	}
      """.stripMargin

    val qThreatTreeGoals = QueryFactory.create(qThreatTreeGoalsString)
    val qThreatTreeGoalsExec = QueryExecutionFactory.create(qThreatTreeGoals, ontModels.adt)
    val threatTreeGoalsResults = qThreatTreeGoalsExec.execSelect().toList
    threatTreeGoalsResults foreach println

    case class InvolvedDFDElThreatTree(dfd: InvolvedDFDElement, goal: OntResource)

    /* Assign each involved DFD element a threat tree. */
    val involvedThreatTrees = involvedDfdElements.flatMap { el =>
      val threatTreeTargetElementString = s"${config.adt._2}#${el.targetElement}"
      threatTreeGoalsResults.find { x =>
        x.getResource("hasTarget").toString == threatTreeTargetElementString
      }
        .map { x =>
          InvolvedDFDElThreatTree(
            dfd = el,
            goal = ontModels.adt.getOntResource(
              x.getResource("goal")
            ).asIndividual()
          )
        }
    }

    println(involvedThreatTrees)

    @tailrec
    def getThreatTrees(
                        involvedThreatTrees: List[InvolvedDFDElThreatTree],
                        accGoals: List[Either[ADTOntModelConverterError, Goal]],
                        accLbls: Map[String, Int]
                      ): (List[Either[ADTOntModelConverterError, Goal]], Map[String, Int]) = involvedThreatTrees match {
      case x :: xs =>
        val res = getADT(config, ontModels, x.goal, accLbls).map { goalAdtTpl =>
          val threatPropertyValue = x.goal.getPropertyValue(getHasTypeProperty(config.adt._2, ontModels.adt))
          val threat = ontModels.adt.getIndividual(threatPropertyValue.asResource().getURI).getLabel("en")
          (goalAdtTpl._1.copy(name = s"${x.dfd.label}: $threat (${x.dfd.id})"), goalAdtTpl._2)
        }
        res match {
          case Right(tpl) => getThreatTrees(xs, Right(tpl._1) :: accGoals, tpl._2)
          case Left(e) => getThreatTrees(xs, Left(e) :: accGoals, accLbls)
        }
      case Nil => (accGoals, accLbls)
    }


    @tailrec
    def buildGoalList(subGoals: List[Either[ADTOntModelConverterError, Goal]], acc: List[Goal] = List()): List[Goal] = subGoals match {
      case x :: xs => x match {
        case Left(err) =>
          println(err)
          buildGoalList(xs, acc)
        case Right(g) =>
          buildGoalList(xs, g :: acc)
      }
      case Nil => acc
    }

    Right(Goal("Obtain Source Code", OrConnector(buildGoalList(getThreatTrees(involvedThreatTrees, List(), Map.empty[String, Int])._1))))
  }

  def getSabotageADT(config: Config, ontModels: OntModels): Either[ADTOntModelConverterError, Goal] = {

    // Get sabotage threat scenario
    val qGetSabotageThreatScenarioString =
      """
        |PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/ADT#>
        |PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        |PREFIX owl: <http://www.w3.org/2002/07/owl#>
        |PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        |PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
        |SELECT ?goal ?hasTarget
        |	WHERE {
        |		?goal rdf:type ?goalType.
        |		?goalType rdfs:subClassOf* ns:Goal.
        |		?goal rdfs:label "Inject Malicious Code Into Source Code"@en.
        |	}
      """.stripMargin


    val qGetSabotageThreatScenario = QueryFactory.create(qGetSabotageThreatScenarioString)
    val qGetSabotageThreatScenarioExec = QueryExecutionFactory.create(qGetSabotageThreatScenario, ontModels.dfd)
    val getSabotageThreatScenario = qGetSabotageThreatScenarioExec.execSelect().toList
    getSabotageThreatScenario foreach println

    val goalsClass = ontModels.adt.getOntClass(config.adt._2 + "#Goal")
    val goals = goalsClass.listInstances().toList
    println(goals)
    val sabotageGoal = goals.filter { r =>
      r.hasLabel("Inject Malicious Code Into Source Code", "en")
    }.toList.headOption
    sabotageGoal match {
      case Some(g) => getADT(config, ontModels, g, Map.empty[String, Int]).map(_._1)
      case None => Left(SubTreeError)
    }
  }

  /**
    * Returns an ADT for a given goal.
    *
    * @param config    the app configuration
    * @param ontModels the ontology models
    * @param goal      the OWL goal
    * @return either an error or the internal representation of the goal
    */
  def getADT(config: Config, ontModels: OntModels, goal: OntResource, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Goal, Map[String, Int])] = {

    val adtOntModel = ontModels.adt
    val dfdOntModel = ontModels.dfd

    val lang = "en"

    /* Define properties. */
    val connectedToProperty = getConnectedToProperty(config.adt._2, adtOntModel)
    val goalClass = getGoalClass(config.adt._2, adtOntModel)
    val andConnectorClass = getAndConnectorClass(config.adt._2, adtOntModel)
    val orConnectorClass = getOrConnectorClass(config.adt._2, adtOntModel)
    val attackNodeClass = getAttackNodeClass(config.adt._2, adtOntModel)
    val defenseNodeClass = getDefenseNodeClass(config.adt._2, adtOntModel)
    val hasTargetProperty = getHasTargetProperty(config.adt._2, adtOntModel)
    val hasTypeProperty = getHasTypeProperty(config.adt._2, adtOntModel)

    /**
      * Returns an [[Individual]] that is connected to (has the property `connectedTo`) a given element.
      *
      * @param el the ontology resource
      * @return an individual that the given element is connected to
      */
    def getConnectedEl(el: OntResource): Individual =
      adtOntModel
        .getIndividual(
          el
            .asIndividual()
            .getProperty(connectedToProperty)
            .getObject
            .toString
        )

    /**
      * Retrieves the complete attack--defense tree, starting from the goal node.
      *
      * @param goalIndv the goal ontology resource
      * @return either an error or the complete tree
      */
    def getGoalTree(goalIndv: Individual, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Goal, Map[String, Int])] = {

      def getUniqueLabel(lbl: String, lblMap: Map[String, Int]): (String, Map[String, Int]) = {
        val cnt = lblMap.getOrElse(lbl, 0)
        val retLbl = if (cnt == 0) lbl else s"$lbl (#$cnt)"
        (retLbl, lblMap + (lbl -> (cnt + 1)))
      }

      /**
        * Retrieves the subtree from a given connector node.
        *
        * @param connIndv the connector ontology resource
        * @return either an error or the subtree
        */
      def getSubTree(connIndv: Individual, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Connector, Map[String, Int])] = {

        /**
          * Recursively retrieve the nodes on the same tree-level, including their subtrees.
          *
          * @param nodeIndvs the nodes in a list
          * @param acc       the accumulator, which consists of a list of attack--defense tree elements
          * @param accLabel  the label accumulator, which consists of a map to uniquely identify labels
          * @return either an error or the internal representation of nodes, including subtrees
          */
        def getADTNodes(nodeIndvs: List[Individual], acc: List[ADTElement] = List(), accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (List[ADTElement], Map[String, Int])] = {

          /**
            * Returns the connector subtree optionally, depending on whether the given node is connected or not.
            *
            * @param n the node to retrieve the connector subtree from
            * @return either an error or the optional connector
            */
          def getOptionalConnector(n: Individual, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Option[Connector], Map[String, Int])] = {
            if (n.asIndividual().hasProperty(connectedToProperty))
              getSubTree(getConnectedEl(n), accLabel).map(tpl => (Some(tpl._1), tpl._2))
            else Right((None, accLabel))
          }

          nodeIndvs match {
            case x :: xs =>
              val unqLblTpl = getUniqueLabel(x.getLabel(lang), accLabel)
              x.getOntClass match {
                case attackNodeC: OntResource if attackNodeC == attackNodeClass =>
                  for {
                    connTpl <- getOptionalConnector(x, unqLblTpl._2)
                    nodes <- getADTNodes(xs, AttackNode(unqLblTpl._1, connTpl._1) :: acc, connTpl._2)
                  } yield nodes

                case defenseNodeC: OntResource if defenseNodeC == defenseNodeClass =>
                  for {
                    connTpl <- getOptionalConnector(x, unqLblTpl._2)
                    nodes <- getADTNodes(xs, DefenseNode(unqLblTpl._1, connTpl._1) :: acc, connTpl._2)
                  } yield nodes

                case goalC: OntResource if goalC == goalClass =>
                  for {
                    g <- getGoalTree(x, unqLblTpl._2)
                    nodes <- getADTNodes(xs, g._1 :: acc, g._2)
                  } yield nodes
                case _ => Left(ADTNodesError)
              }
            case Nil => Right((acc, accLabel))
          }
        }

        /**
          * Returns an instance of [[Connector]] from the OWL resource that represents a connector.
          *
          * @param ci  the connector individual
          * @param cls the class that is used for instantiating the connector, either [[AndConnector]] or [[OrConnector]]
          * @return either an error or the connector
          */
        def getConnector(ci: Individual, cls: Class[_], accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Connector, Map[String, Int])] = {
          if (cls == classOf[AndConnector] || cls == classOf[OrConnector]) {
            val nodeIndvs =
              connIndv.listProperties(connectedToProperty)
                .map(stmt => adtOntModel.getIndividual(stmt.getObject.toString))
                .toList

            if (nodeIndvs.nonEmpty) {
              /* For the list of nodes, we want to get each subtree. */
              getADTNodes(nodeIndvs, accLabel = accLabel)
                .map {
                  case (l, m) =>
                    /* After receiving all subtrees, instantiate instance of `AndConnector` or `OrConnector` to connect the nodes. */
                    val constructor = cls.getConstructors()(0)
                    val args = Array[AnyRef](l)
                    (constructor.newInstance(args: _*).asInstanceOf[Connector], m)
                }
            } else {
              val target = connIndv.listProperties(hasTargetProperty)
                .map(stmt => dfdOntModel.getIndividual(stmt.getObject.toString))
                .toList.headOption
              val threatTypes = connIndv.listProperties(hasTypeProperty)
                .map(stmt => adtOntModel.getIndividual(stmt.getObject.toString))
                .toList

              val nodeIndvsByThreats = target.map(t => getNodeIndvsByThreats(config, ontModels, t, threatTypes)).getOrElse(Nil)

              /* After receiving all subtrees, instantiate instance of `AndConnector` or `OrConnector` to connect the nodes. */
              val constructor = cls.getConstructors()(0)
              val args = Array[AnyRef](nodeIndvsByThreats)
              Right((constructor.newInstance(args: _*).asInstanceOf[Connector], accLabel))
            }
          } else
            Left(NotAConnectorOwlResource)
        }

        /* Match connector ont resource. */
        connIndv.getOntClass match {
          /* AND Connector */
          case andConnectorC: OntResource if andConnectorC == andConnectorClass =>
            getConnector(connIndv, classOf[AndConnector], accLabel)

          /* OR Connector */
          case orConnectorC: OntResource if orConnectorC == orConnectorClass =>
            getConnector(connIndv, classOf[OrConnector], accLabel)

          /* Ont resource is neither AND nor OR connector. */
          case _ => Left(SubTreeError)
        }
      }

      /* Match goal ont resource. */
      goalIndv.getOntClass match {
        case goalC: OntResource if goalC == goalClass =>
          getSubTree(getConnectedEl(goalIndv), accLabel)
            /* Map result to instance of `Goal`. */
            .map { c =>
            val unqLblTpl = getUniqueLabel(goalIndv.getLabel(lang), c._2)
            (Goal(unqLblTpl._1, c._1), unqLblTpl._2)
          }
        /* Return error, if ont resource has not the class `Goal`. */
        case _ => Left(GoalSubTreeError)
      }

    }

    /* Start processing... */
    getGoalTree(goal.asIndividual(), accLabel)

  }

  def getNodeIndvsByThreats(config: Config, ontModels: OntModels, target: Individual, threatTypes: List[Individual]): List[Goal] = {

    // Get all DFD elements that use a given asset
    val qGetDfdElementsByAssetString =
      s"""
         |PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
         |PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
         |PREFIX owl: <http://www.w3.org/2002/07/owl#>
         |PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
         |PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
         |SELECT ?asset ?individual ?id
         |	WHERE {
         |		?asset rdf:type ?assetType.
         |		?assetType rdfs:subClassOf* ns:Asset.
         |		?asset ns:usedBy ?individual.
         |		?individual ns:id ?id.
         |		?asset rdfs:label "${target.getLabel("en")}"@en.
         |	}
         |ORDER BY ?asset
      """.stripMargin

    val qGetDfdElementsByAsset = QueryFactory.create(qGetDfdElementsByAssetString)
    val qGetDfdElementsByAssetExec = QueryExecutionFactory.create(qGetDfdElementsByAsset, ontModels.dfd)
    val getDfdElementsByAsset = qGetDfdElementsByAssetExec.execSelect().toList
    getDfdElementsByAsset foreach println

    case class InvolvedDFDElement(id: String, label: String, targetElement: String)

    val classes = List(
      getDataFlowClass(config.dfd._2, ontModels.dfd),
      getExternalEntityClass(config.dfd._2, ontModels.dfd),
      getProcessClass(config.dfd._2, ontModels.dfd),
      getDataStoreClass(config.dfd._2, ontModels.dfd)
    )

    val involvedDfdElements: List[InvolvedDFDElement] = getDfdElementsByAsset.flatMap { r =>
      val usedByIndv = r.getResource("individual")
      val usedByIndvId = r.getLiteral("?id")
      val indv = ontModels.dfd.getOntResource(usedByIndv).asIndividual()
      val cls = classes.find(c => indv.hasOntClass(c))
      cls match {
        case Some(dataFlowClass: OntResource) if dataFlowClass == getDataFlowClass(config.dfd._2, ontModels.dfd) =>
          val stmts = indv.listProperties().toList.filter { s =>
            s.getPredicate == getFlowsProperty(config.dfd._2, ontModels.dfd) ||
              s.getPredicate == getFlowsToProperty(config.dfd._2, ontModels.dfd) ||
              s.getPredicate == getFlowsFromProperty(config.dfd._2, ontModels.dfd)
          }
          val flowList = stmts.map { s =>
            val verb = OntModelUtils.removeNamespace(s.getPredicate.toString)
            val flowTarget = ontModels.dfd.getIndividual(s.getObject.toString).getLabel("en")
            s"$verb $flowTarget"
          }
          val label = s"${indv.getLabel("en")} [${flowList.mkString(" and ")}]"
          Some(InvolvedDFDElement(usedByIndvId.getString, label, OntModelUtils.removeNamespace(dataFlowClass.toString)))
        case Some(c) => Some(InvolvedDFDElement(usedByIndvId.getString, indv.getLabel("en"), OntModelUtils.removeNamespace(c.toString)))
        case _ => None
      }
    }

    println(involvedDfdElements)

    val targetList = involvedDfdElements.map(e => s"ns:${e.targetElement}").distinct.mkString(", ")

    val threatTypesStr = threatTypes.map(s => s"ns:${OntModelUtils.removeNamespace(s.toString)}").distinct.mkString(", ")
    println(threatTypesStr)
    // Query all goals that have as target `targetElement` and as `hasType` STRIDE threat

    val qThreatTreeGoalsString =
      s"""
         |PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/ADT#>
         |PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
         |PREFIX owl: <http://www.w3.org/2002/07/owl#>
         |PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
         |PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
         |SELECT ?goal ?hasTarget
         |	WHERE {
         |		?goal rdf:type ?goalType.
         |		?goalType rdfs:subClassOf* ns:Goal.
         |		?goal ns:hasTarget ?hasTarget.
         |		?goal ns:hasType ?hasType.
         |		FILTER(?hasTarget IN ($targetList) && ?hasType IN ($threatTypesStr))
         |	}
      """.stripMargin

    val qThreatTreeGoals = QueryFactory.create(qThreatTreeGoalsString)
    val qThreatTreeGoalsExec = QueryExecutionFactory.create(qThreatTreeGoals, ontModels.adt)
    val threatTreeGoalsResults = qThreatTreeGoalsExec.execSelect().toList
    threatTreeGoalsResults foreach println
    // threatTreeGoalsResults.map { x =>
    //  ontModels.adt.getOntResource(x.getResource("goal").toString).asIndividual()
    // }

    case class InvolvedDFDElThreatTree(dfd: InvolvedDFDElement, goal: OntResource)

    /* Assign each involved DFD element a threat tree. */
    val involvedThreatTrees = involvedDfdElements.flatMap { el =>
      val threatTreeTargetElementString = s"${config.adt._2}#${el.targetElement}"
      threatTreeGoalsResults.find { x =>
        x.getResource("hasTarget").toString == threatTreeTargetElementString
      }
        .map { x =>
          InvolvedDFDElThreatTree(
            dfd = el,
            goal = ontModels.adt.getOntResource(
              x.getResource("goal")
            ).asIndividual()
          )
        }
    }

    println(involvedThreatTrees)

    @tailrec
    def getThreatTrees(
                        involvedThreatTrees: List[InvolvedDFDElThreatTree],
                        accGoals: List[Either[ADTOntModelConverterError, Goal]],
                        accLbls: Map[String, Int]
                      ): (List[Either[ADTOntModelConverterError, Goal]], Map[String, Int]) = involvedThreatTrees match {
      case x :: xs =>
        val res = getADT(config, ontModels, x.goal, accLbls).map { goalAdtTpl =>
          val threatPropertyValue = x.goal.getPropertyValue(getHasTypeProperty(config.adt._2, ontModels.adt))
          val threat = ontModels.adt.getIndividual(threatPropertyValue.asResource().getURI).getLabel("en")
          (goalAdtTpl._1.copy(name = s"${x.dfd.label}: $threat (${x.dfd.id})"), goalAdtTpl._2)
        }
        res match {
          case Right(tpl) => getThreatTrees(xs, Right(tpl._1) :: accGoals, tpl._2)
          case Left(e) => getThreatTrees(xs, Left(e) :: accGoals, accLbls)
        }
      case Nil => (accGoals, accLbls)
    }


    @tailrec
    def buildGoalList(subGoals: List[Either[ADTOntModelConverterError, Goal]], acc: List[Goal] = List()): List[Goal] = subGoals match {
      case x :: xs => x match {
        case Left(err) =>
          println(err)
          buildGoalList(xs, acc)
        case Right(g) =>
          buildGoalList(xs, g :: acc)
      }
      case Nil => acc
    }

    buildGoalList(getThreatTrees(involvedThreatTrees, List(), Map.empty[String, Int])._1)

  }

}
