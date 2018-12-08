package org.sba_research

import org.sba_research.model._

import scala.xml.{Elem, Node}


sealed trait ADTXMLError

case object AddChildError extends ADTXMLError

case object ADTNodeError extends ADTXMLError


object ADTXMLMarshaller {

  def execute(outputDir: String, adt: Goal): Unit = {

    val p = new scala.xml.PrettyPrinter(80, 4)

    /**
      * Adds a child node to a given node.
      *
      * Based on https://stackoverflow.com/a/2200651/5107545.
      *
      * @param n        the existing, base node
      * @param newChild the node to add
      * @return
      */
    def addChild(n: Node, newChild: Node): Either[ADTXMLError, Node] = n match {
      case Elem(prefix, label, attribs, scope, child@_*) =>
        Right(Elem(prefix, label, attribs, scope, child ++ newChild: _*))
      case _ =>
        Left(AddChildError)
    }

    def getAdtGoalNode(adt: Goal): Either[ADTXMLError, Node] = {

      /**
        * Returns the connector name, either `conjunctive` for and or `disjunctive` for or.
        *
        * @param c the connector to check
        * @return the connector name
        */
      def getConnectorName(c: Connector): String = c match {
        case _: AndConnector => "conjunctive"
        case _: OrConnector => "disjunctive"
      }

      /**
        * Returns an XML node for a given [[ADTElement]].
        *
        * @param adtEl         the attack--defense tree element
        * @param parentElement the parent attack-defense tree element (used to determine if `switchRole` should be set)
        * @return an XML node, representing the attack--defense tree element
        */
      def getAdtNode(adtEl: ADTElement, parentElement: Option[ADTElement]): Node = {
        val label = adtEl.name
        val refinement = adtEl match {
          case g: Goal => getConnectorName(g.connector)
          case n: ADTNode => n.connector.map(getConnectorName).getOrElse("disjunctive")
        }
        val switchRole: Option[String] = parentElement flatMap { p =>
          /* If parent node and current node are an instance of a different class, (attackNode/defenseNode or defenseNode/attackNode), set switchRole. */
          if (p.isInstanceOf[DefenseNode] != adtEl.isInstanceOf[DefenseNode]) Some("yes")
          else None
        }

        <node refinement={refinement} switchRole={switchRole orNull}>
          <label>
            {label}
          </label>
        </node>
      }

      /**
        * Converts the internal representation of an attack--defense tree to an XML node.
        *
        * @param adtEl    the attack--defense tree element to transform
        * @param accNode  the accumulator node
        * @param parentEl the parent element (only used to determine whether `switchRole` should be active or not)
        * @return an error or an XML node
        */
      def convertToXMLNodes(adtEl: ADTElement, accNode: Node, parentEl: Option[ADTElement]): Either[ADTXMLError, Node] = {

        /**
          * Processes connected nodes.
          *
          * @param accNode the accumulator node (contains the latest version of the XML node to build)
          * @param acc     the accumulator list (contains attack--defense tree elements that are connected to the parent element)
          * @param parent  the parent element (only used to determine whether `switchRole` should be active or not)
          * @return an error or an XML node
          */
        def processConnectedNodes(accNode: Node, acc: List[ADTElement], parent: Option[ADTElement]): Either[ADTXMLError, Node] = acc match {
          case x :: xs => convertToXMLNodes(x, accNode, parent).flatMap(r => processConnectedNodes(r, xs, parent))
          case Nil => Right(accNode)
        }

        adtEl match {
          case g: Goal =>
            /* Go one hierarchy down... (process connected nodes) */
            processConnectedNodes(
              accNode = getAdtNode(g, parentEl),
              acc = g.connector.nodes,
              parent = Some(g)
            )
              /* Add the XML node, including all children, to the parent node element. */
              .flatMap(r => addChild(accNode, r))
          case n: ADTNode => n.connector match {
            case Some(con) =>
              processConnectedNodes(
                accNode = getAdtNode(n, parentEl),
                acc = con.nodes,
                parent = Some(n)
              )
                .flatMap(r => addChild(accNode, r))
            case None => addChild(accNode, getAdtNode(n, parentEl))
          }
        }

      }

      /* The initial parent node. */
      val adtNode = <adtree></adtree>

      convertToXMLNodes(adt, adtNode, None)
    }

    /**
      * Writes the XML to a file.
      *
      * @param n the node to write
      */
    def writeXml(n: Node): Unit = scala.xml.XML.save(outputDir, n, "UTF-8", xmlDecl = true, null)


    getAdtGoalNode(adt) match {
      case Right(n) =>
        println(p.format(n))
        writeXml(n)
      case Left(AddChildError) => println("Can only add children to elements!")
      case Left(_) => println("Error!")
    }

  }

}
