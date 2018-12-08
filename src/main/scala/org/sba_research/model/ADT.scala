package org.sba_research.model


trait ADTElement {
  val name: String
}

trait ADTNode extends ADTElement {
  val connector: Option[Connector]
}

trait Connector {
  val nodes: List[ADTElement]
}

case class Goal(name: String, connector: Connector) extends ADTElement

case class AttackNode(name: String, connector: Option[Connector] = None) extends ADTNode

case class DefenseNode(name: String, connector: Option[Connector] = None) extends ADTNode

case class OrConnector(nodes: List[ADTElement]) extends Connector

case class AndConnector(nodes: List[ADTElement]) extends Connector
