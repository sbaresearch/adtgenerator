package org.sba_research

import org.apache.jena.ontology.{Individual, OntModel, OntResource}
import org.apache.jena.query.{QueryExecutionFactory, QueryFactory}
import org.sba_research.model._

import scala.annotation.tailrec
import scala.collection.JavaConversions._

/**
  * Converts the ADT ontology model to the internal ADT representation.
  */
object ADTOntModelConverter {

  sealed trait ADTOntModelConverterError

  case class InvolvedDFDElement(id: String, label: String, targetElement: String)

  case class InvolvedDFDElThreatTree(dfd: InvolvedDFDElement, goal: OntResource)

  case object GoalSubTreeError extends ADTOntModelConverterError

  case object SubTreeError extends ADTOntModelConverterError

  case object ADTNodesError extends ADTOntModelConverterError

  case object NotAConnectorOwlResource extends ADTOntModelConverterError

  case object StrideMapKeyNotFoundError extends ADTOntModelConverterError

  case object SabotageGoalNotFoundError extends ADTOntModelConverterError

  private val flowsFromProperty = "#flowsFrom"

  private val flowsToProperty = "#flowsTo"

  private val flowsProperty = "#flows"

  private val connectedToProperty = "#connectedTo"

  private val hasTypeProperty = "#hasType"

  private val hasTargetProperty = "#hasTarget"

  private val goalClass = "#Goal"

  private val orConnectorClass = "#OrConnector"

  private val andConnectorClass = "#AndConnector"

  private val attackNodeClass = "#AttackNode"

  private val defenseNodeClass = "#DefenseNode"

  private val processClass = "#Process"

  private val dataStoreClass = "#DataStore"

  private val dataFlowClass = "#DataFlow"

  private val externalEntityClass = "#ExternalEntity"

  /**
    * Retrieves the [[org.apache.jena.ontology.OntClass]] instance by its label.
    *
    * @param ns       the namespace
    * @param ontModel the ontology model
    * @param label    the label to retrieve the class from
    * @return the ontology class
    */
  private def getResourceClass(ns: String, ontModel: OntModel, label: String) = ontModel.getOntClass(ns + label)

  /**
    * Retrieves the [[org.apache.jena.ontology.OntProperty]] instance by its label.
    *
    * @param ns       the namespace
    * @param ontModel the ontology model
    * @param label    the label to retrieve the resource property from
    * @return the resource property
    */
  private def getResourceProperty(ns: String, ontModel: OntModel, label: String) = ontModel.getOntProperty(ns + label)

  /**
    * A map that consists of pairs of STRIDE keys and values (labels).
    * This map is used to retrieve the labels of STRIDE threats when generating a plain ADT.
    */
  private val threatMap = Map('S' -> "Spoofing", 'T' -> "Tampering", 'R' -> "Repudiation", 'I' -> "InformationDisclosure", 'D' -> "DenialOfService", 'E' -> "ElevationOfPrivilege")

  /**
    * Retrieves an ADT that has a STRIDE threat as a goal and targets a specific asset.
    *
    * @param config    the app config
    * @param ontModels the ontology models
    * @param threatKey the STRIDE threat key (S, T, R, I, D, E)
    * @param asset     the targeted asset
    * @return either an error or the (converted) internal representation of the ADT
    */
  def getPlainADT(config: Config, ontModels: OntModels, threatKey: Char, asset: String): Either[ADTOntModelConverterError, Goal] = {
    // Retrieve threat type by STRIDE key
    threatMap.get(threatKey)
      .flatMap { threatType =>
        // Retrieve all DFD elements that 'use' the asset
        val involvedDfdElements = getInvolvedDfdElements(dfdNs = config.dfd._2, dfdOntModel = ontModels.dfd, asset = asset)
        // Build target list (used in query)
        val targetList = involvedDfdElements.map(e => s"ns:${e.targetElement}").distinct.mkString(", ")
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
        // Retrieve all threat trees of all DFD elements that use the asset
        val involvedThreatTrees = getInvolvedThreatTrees(adtNs = config.adt._2, adtOntModel = ontModels.adt, query = qThreatTreeGoalsString, involvedDfdElements = involvedDfdElements)
        // Return result
        Some(
          Right(
            Goal(
              name = s"$threatType -> $asset",
              connector = OrConnector(
                nodes = buildGoalList(
                  getThreatTrees(config = config, ontModels = ontModels, involvedThreatTrees = involvedThreatTrees)._1
                )
              )
            )
          )
        )
      }.getOrElse(
      // STRIDE key does not exist in map
      Left(StrideMapKeyNotFoundError)
    )
  }

  /**
    * Retrieves an ADT for a sabotage threat scenario.
    *
    * @param config    the app config
    * @param ontModels the ontology models
    * @param goal      the sabotage goal to build the ADT
    * @return either an error or the (converted) internal representation of the ADT
    */
  def getSabotageADT(config: Config, ontModels: OntModels, goal: String): Either[ADTOntModelConverterError, Goal] = {
    // Get goal class
    val goalClass = ontModels.adt.getOntClass(config.adt._2 + "#Goal")
    val goals = goalClass
      .listInstances()
      .toList
    // Retrieve sabotage goal from list of instances
    goals.filter(r => r.hasLabel(goal, "en"))
      .toList
      .headOption
      // Retrieve ADT
      .flatMap { g =>
      Some(
        getADT(config = config, ontModels = ontModels, goal = g, accLabel = Map.empty[String, Int]).map(_._1)
      )
    }
      .getOrElse(
        // Could not find request sabotage goal in goals list
        Left(SabotageGoalNotFoundError)
      )
  }

  /**
    * Returns either an error or an ADT for a given goal.
    *
    * @param config    the app configuration
    * @param ontModels the ontology models
    * @param goal      the OWL goal
    * @return either an error or the internal representation of the goal
    */
  private def getADT(config: Config, ontModels: OntModels, goal: OntResource, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Goal, Map[String, Int])] = {
    // Temp values for ont models
    val adtOntModel = ontModels.adt
    val dfdOntModel = ontModels.dfd
    // Label language
    val lang = "en"
    /* Define properties and classes. */
    val connectedToProp = getResourceProperty(config.adt._2, adtOntModel, connectedToProperty)
    val goalClazz = getResourceClass(config.adt._2, adtOntModel, goalClass)
    val andConnectorClazz = getResourceClass(config.adt._2, adtOntModel, andConnectorClass)
    val orConnectorClazz = getResourceClass(config.adt._2, adtOntModel, orConnectorClass)
    val attackNodeClazz = getResourceClass(config.adt._2, adtOntModel, attackNodeClass)
    val defenseNodeClazz = getResourceClass(config.adt._2, adtOntModel, defenseNodeClass)
    val hasTargetProp = getResourceProperty(config.adt._2, adtOntModel, hasTargetProperty)
    val hasTypeProp = getResourceProperty(config.adt._2, adtOntModel, hasTypeProperty)

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
            .getProperty(connectedToProp)
            .getObject
            .toString
        )

    /**
      * Retrieves the complete attack--defense tree, starting from the goal node.
      *
      * @param goalIndv the goal ontology resource
      * @param accLabel the accumulator label map
      * @return either an error or the complete tree
      */
    def getGoalTree(goalIndv: Individual, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Goal, Map[String, Int])] = {

      /**
        * Returns a tuple consisting of a label that is unique within the ADT and the accumulator label map.
        *
        * @param lbl    the original label that may not be unique
        * @param lblMap the label map
        * @return a tuple consisting of a unique label and the accumulator label map
        */
      def getUniqueLabel(lbl: String, lblMap: Map[String, Int]): (String, Map[String, Int]) = {
        val cnt = lblMap.getOrElse(lbl, 0)
        val retLbl = if (cnt == 0) lbl else s"$lbl (#$cnt)"
        (retLbl, lblMap + (lbl -> (cnt + 1)))
      }

      /**
        * Retrieves the subtree from a given connector node.
        *
        * @param connIndv the connector ontology resource
        * @param accLabel the accumulator label map
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
            * Returns the connector subtree optionally, depending on whether the given node is connected to something or not.
            *
            * @param n        the node to retrieve the connector subtree from
            * @param accLabel the accumulator label map
            * @return either an error or the optional connector
            */
          def getOptionalConnector(n: Individual, accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Option[Connector], Map[String, Int])] = {
            if (n.asIndividual().hasProperty(connectedToProp))
              getSubTree(connIndv = getConnectedEl(n), accLabel = accLabel).map(tpl => (Some(tpl._1), tpl._2))
            else Right((None, accLabel))
          }

          // Match list of nodes on the same tree level
          nodeIndvs match {
            case x :: xs =>
              // Retrieve unique label
              val unqLblTpl = getUniqueLabel(lbl = x.getLabel(lang), lblMap = accLabel)
              // Match per ontology class
              x.getOntClass match {
                // Check whether current node is attacker node
                case attackNodeC: OntResource if attackNodeC == attackNodeClazz =>
                  for {
                    connTpl <- getOptionalConnector(n = x, accLabel = unqLblTpl._2)
                    nodes <- getADTNodes(nodeIndvs = xs, acc = AttackNode(unqLblTpl._1, connTpl._1) :: acc, accLabel = connTpl._2)
                  } yield nodes
                // Check whether current node is defense node
                case defenseNodeC: OntResource if defenseNodeC == defenseNodeClazz =>
                  for {
                    connTpl <- getOptionalConnector(n = x, accLabel = unqLblTpl._2)
                    nodes <- getADTNodes(nodeIndvs = xs, acc = DefenseNode(unqLblTpl._1, connTpl._1) :: acc, accLabel = connTpl._2)
                  } yield nodes
                // Check whether current node is goal
                case goalC: OntResource if goalC == goalClazz =>
                  for {
                    g <- getGoalTree(goalIndv = x, accLabel = unqLblTpl._2)
                    nodes <- getADTNodes(nodeIndvs = xs, acc = g._1 :: acc, accLabel = g._2)
                  } yield nodes
                // Node class does not match attack, defense or goal
                case _ => Left(ADTNodesError)
              }
            // All nodes on the current tree level have been processed, return...
            case Nil => Right((acc, accLabel))
          }
        }

        /**
          * Returns an instance of [[Connector]] from the OWL resource that represents a connector.
          *
          * @param ci       the connector individual
          * @param cls      the class that is used for instantiating the connector, either [[AndConnector]] or [[OrConnector]]
          * @param accLabel the accumulator label map
          * @return either an error or the connector
          */
        def getConnector(ci: Individual, cls: Class[_], accLabel: Map[String, Int]): Either[ADTOntModelConverterError, (Connector, Map[String, Int])] = {
          // Check whether class arg is really a supported connector
          if (cls == classOf[AndConnector] || cls == classOf[OrConnector]) {
            // Get all node individuals that are connected with the current connector under process
            val nodeIndvs =
              connIndv
                .listProperties(connectedToProp)
                .map(stmt => adtOntModel.getIndividual(stmt.getObject.toString))
                .toList

            // If list of connected nodes is not empty, retrieve each subtree
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
            } else { // No nodes are connected to the current connector under process
              /*
               * Sabotage ADTs are typically composed of the following subtrees 'Reconnaissance', 'Sabotage', and 'Concealment'.
               * 'Reconnaissance' and 'Concealment' subtrees may have a connector that has the properties `hasType` (e.g., Tampering) and `hasTarget` (e.g., Test Incident Report).
               * These properties are used to retrieve a plain STRIDE threat tree.
               */
              // Retrieve target
              val target =
              connIndv
                .listProperties(hasTargetProp)
                .map(stmt => dfdOntModel.getIndividual(stmt.getObject.toString))
                .toList.headOption
              // Retrieve threat types; can be more than one
              val threatTypes =
                connIndv
                  .listProperties(hasTypeProp)
                  .map(stmt => adtOntModel.getIndividual(stmt.getObject.toString))
                  .toList
              // Retrieve threat tree for each threat type
              val threatTrees =
                target
                  .map(t => getThreatTreesByAssetAndThreats(config = config, ontModels = ontModels, target = t, threatTypes = threatTypes))
                  .getOrElse(Nil)
              /* After receiving all subtrees, instantiate instance of `AndConnector` or `OrConnector` to connect the nodes. */
              val constructor = cls.getConstructors()(0)
              val args = Array[AnyRef](threatTrees)
              Right(
                (constructor.newInstance(args: _*).asInstanceOf[Connector], accLabel)
              )
            }
          } else // Unsupported connector
            Left(NotAConnectorOwlResource)
        }

        /* Match connector ont resource. */
        connIndv.getOntClass match {
          /* AND Connector */
          case andConnectorC: OntResource if andConnectorC == andConnectorClazz =>
            getConnector(connIndv, classOf[AndConnector], accLabel)
          /* OR Connector */
          case orConnectorC: OntResource if orConnectorC == orConnectorClazz =>
            getConnector(connIndv, classOf[OrConnector], accLabel)
          /* Ont resource is neither AND nor OR connector. */
          case _ => Left(SubTreeError)
        }
      }

      /* Match goal ont resource. */
      goalIndv.getOntClass match {
        case goalC: OntResource if goalC == goalClazz =>
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

  /**
    * Retrieves a list of threat trees targeting a specific asset that is put at risk by one or multiple threats.
    *
    * @param config      the app config
    * @param ontModels   the ontology models
    * @param target      the asset (e.g., test incident report) as an individual
    * @param threatTypes the threat types (e.g., InformationDisclosure, Tampering)
    * @return a list of threat trees
    */
  private def getThreatTreesByAssetAndThreats(config: Config, ontModels: OntModels, target: Individual, threatTypes: List[Individual]): List[Goal] = {
    // Get asset
    val asset = target.getLabel("en")
    // Get all DFD elements that use the asset somehow
    val involvedDfdElements = getInvolvedDfdElements(config.dfd._2, ontModels.dfd, asset)
    // Build target list
    val targetList = involvedDfdElements.map(e => s"ns:${e.targetElement}").distinct.mkString(", ")
    // Build threat types list
    val threatTypesStr = threatTypes.map(s => s"ns:${OntModelUtils.removeNamespace(s.toString)}").distinct.mkString(", ")
    // Query all goals that have as target one in the target list and as STRIDE threat one in the threat type list
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
    // Retrieve all threat trees
    val involvedThreatTrees = getInvolvedThreatTrees(adtNs = config.adt._2, adtOntModel = ontModels.adt, query = qThreatTreeGoalsString, involvedDfdElements = involvedDfdElements)
    // Build goal list
    buildGoalList(
      subGoals = getThreatTrees(config = config, ontModels = ontModels, involvedThreatTrees = involvedThreatTrees)._1
    )
  }

  /**
    * Retrieves all DFD elements that use the asset somehow.
    *
    * @param dfdNs       the DFD ontology namespace
    * @param dfdOntModel the DFD ontology model
    * @param asset       the asset
    * @return a list of involved DFD elements
    */
  private def getInvolvedDfdElements(dfdNs: String, dfdOntModel: OntModel, asset: String): List[InvolvedDFDElement] = {
    // Query string to get all DFD elements that use a given asset
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
         |		?asset rdfs:label "$asset"@en.
         |	}
         |ORDER BY ?asset
      """.stripMargin
    // Create the query
    val qGetDfdElementsByAsset = QueryFactory.create(qGetDfdElementsByAssetString)
    // Create the query execution
    val qGetDfdElementsByAssetExec = QueryExecutionFactory.create(qGetDfdElementsByAsset, dfdOntModel)
    // Execute query
    val getDfdElementsByAsset = qGetDfdElementsByAssetExec.execSelect().toList
    // Define resource classes
    val classes = List(
      getResourceClass(dfdNs, dfdOntModel, dataFlowClass),
      getResourceClass(dfdNs, dfdOntModel, externalEntityClass),
      getResourceClass(dfdNs, dfdOntModel, processClass),
      getResourceClass(dfdNs, dfdOntModel, dataStoreClass)
    )
    // Evaluate query result and populate DFD elements
    val involvedDfdElements: List[InvolvedDFDElement] = getDfdElementsByAsset.flatMap { r =>
      val usedByIndv = r.getResource("individual")
      val usedByIndvId = r.getLiteral("?id")
      val indv = dfdOntModel.getOntResource(usedByIndv).asIndividual()
      // Find class of individual
      val cls = classes.find(c => indv.hasOntClass(c))
      // Match class of individual
      cls match {
        // Individual has class `DataFlow`
        case Some(dfClass: OntResource) if dfClass == getResourceClass(dfdNs, dfdOntModel, dataFlowClass) =>
          // Get values of flows/flowsTo/flowsFrom properties
          val stmts = indv.listProperties().toList.filter { s =>
            s.getPredicate == getResourceProperty(dfdNs, dfdOntModel, flowsProperty) ||
              s.getPredicate == getResourceProperty(dfdNs, dfdOntModel, flowsToProperty) ||
              s.getPredicate == getResourceProperty(dfdNs, dfdOntModel, flowsFromProperty)
          }
          // Build flows list
          val flowList = stmts.map { s =>
            val verb = OntModelUtils.removeNamespace(s.getPredicate.toString)
            val flowTarget = dfdOntModel.getIndividual(s.getObject.toString).getLabel("en")
            s"$verb $flowTarget"
          }
          // Create label
          val label = s"${indv.getLabel("en")} [${flowList.mkString(" and ")}]"
          // Return result
          Some(InvolvedDFDElement(usedByIndvId.getString, label, OntModelUtils.removeNamespace(dfClass.toString)))
        // Any other class
        case Some(c) => Some(InvolvedDFDElement(usedByIndvId.getString, indv.getLabel("en"), OntModelUtils.removeNamespace(c.toString)))
        // Unknown class
        case _ => None
      }
    }
    // Return
    involvedDfdElements
  }

  /**
    * Retrieves all threat trees that put a certain asset at risk (asset is used by DFD elements somehow).
    *
    * @param adtNs               the ADT ontology namespace
    * @param adtOntModel         the ADT ontology model
    * @param query               the query string
    * @param involvedDfdElements the DFD elements that use the asset
    * @return
    */
  private def getInvolvedThreatTrees(adtNs: String, adtOntModel: OntModel, query: String, involvedDfdElements: List[InvolvedDFDElement]): List[InvolvedDFDElThreatTree] = {
    // Create query
    val qThreatTreeGoals = QueryFactory.create(query)
    // Create query execution
    val qThreatTreeGoalsExec = QueryExecutionFactory.create(qThreatTreeGoals, adtOntModel)
    // Run query
    val threatTreeGoalsResults = qThreatTreeGoalsExec.execSelect().toList

    /* Assign each involved DFD element a threat tree. */
    val involvedThreatTrees = involvedDfdElements.flatMap { el =>
      // Build target element string (e.g., ADT#DataFlow)
      val threatTreeTargetElementString = s"$adtNs#${el.targetElement}"
      // Find all threat trees that have the target as property value
      threatTreeGoalsResults.find { x =>
        x.getResource("hasTarget").toString == threatTreeTargetElementString
      }
        .map { x =>
          // Build involved DFD element threat tree
          InvolvedDFDElThreatTree(
            dfd = el,
            goal = adtOntModel.getOntResource(
              x.getResource("goal")
            ).asIndividual()
          )
        }
    }
    involvedThreatTrees
  }

  /**
    * Retrieves a list consisting of either an error or a threat tree.
    *
    * @param config              the app config
    * @param ontModels           the ontology models
    * @param involvedThreatTrees the involved threat trees
    * @param accGoals            the accumulator for goals
    * @param accLbls             the accumulator for labels
    * @return a list composed of either an error or a threat tree
    */
  @tailrec
  private def getThreatTrees(
                              config: Config,
                              ontModels: OntModels,
                              involvedThreatTrees: List[InvolvedDFDElThreatTree],
                              accGoals: List[Either[ADTOntModelConverterError, Goal]] = List(),
                              accLbls: Map[String, Int] = Map.empty[String, Int]
                            ): (List[Either[ADTOntModelConverterError, Goal]], Map[String, Int]) = involvedThreatTrees match {
    case x :: xs =>
      // Get either an error or the ADT
      val res = getADT(config = config, ontModels = ontModels, goal = x.goal, accLabel = accLbls)
        .map { goalAdtTpl =>
          // Retrieve threat for goal name
          val threatPropertyValue = x.goal.getPropertyValue(getResourceProperty(config.adt._2, ontModels.adt, hasTypeProperty))
          val threat = ontModels.adt.getIndividual(threatPropertyValue.asResource().getURI).getLabel("en")
          // Rename goal
          (goalAdtTpl._1.copy(name = s"${x.dfd.label}: $threat (${x.dfd.id})"), goalAdtTpl._2)
        }
      // Check for potential errors
      res match {
        // No error, add goal to goal accumulator and call this method again
        case Right(tpl) => getThreatTrees(
          config = config,
          ontModels = ontModels,
          involvedThreatTrees = xs,
          accGoals = Right(tpl._1) :: accGoals,
          accLbls = tpl._2
        )
        // Error, add error to goal accumulator and re-use labels accumulator
        case Left(e) => getThreatTrees(
          config = config,
          ontModels = ontModels,
          involvedThreatTrees = xs,
          accGoals = Left(e) :: accGoals,
          accLbls = accLbls
        )
      }
    case Nil => (accGoals, accLbls)
  }

  /**
    * Builds recursively a goal list. This method is used to resolve potential errors.
    *
    * @param subGoals a list of sub goals, consisting either of an error or the goal
    * @param acc      the accumulator
    * @return a list of goals
    */
  @tailrec
  private def buildGoalList(subGoals: List[Either[ADTOntModelConverterError, Goal]], acc: List[Goal] = List()): List[Goal] = subGoals match {
    case x :: xs => x match {
      // Check whether an error occurred
      case Left(err) =>
        // Print error
        println(err)
        // Do not add goal to accumulator
        buildGoalList(xs, acc)
      case Right(g) =>
        // Add goal to accumulator
        buildGoalList(xs, g :: acc)
    }
    // Done, return list of goals
    case Nil => acc
  }

}
