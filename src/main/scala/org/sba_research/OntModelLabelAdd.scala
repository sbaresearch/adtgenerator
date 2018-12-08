package org.sba_research


import org.apache.commons.lang3.StringUtils

import scala.xml.transform.{RewriteRule, RuleTransformer}
import scala.xml.{Elem, Node, XML}

object OntModelLabelAdd {

  def main(args: Array[String]): Unit = {

    val config = Config()
    val adtOwl = XML.loadFile("/home/meckhart/Development/CPS/m1-testing-process/software-testing-adtrees-generator/src/main/resources/DFD.owl")

    val addLabel: RewriteRule = new RewriteRule() {
      override def transform(node: Node): Node = node match {
        case e: Elem if e.label == "NamedIndividual" =>
          addChild(e,
            <rdfs:label xml:lang="en">{getName(e)}</rdfs:label>
          ).getOrElse(e)
        case other => other
      }
    }

    val addLabelTransformer = new RuleTransformer(addLabel)

    writeModel(addLabelTransformer(adtOwl))

  }


  def writeModel(modelNode: Node): Unit = XML.save("test.xml", modelNode, "UTF-8", xmlDecl = true, null)

  def addChild(n: Node, newChild: Node): Option[Node] = n match {
    case Elem(prefix, label, attribs, scope, child@_*) =>
      Some(Elem(prefix, label, attribs, scope, child ++ newChild: _*))
    case _ =>
      println("Can only add children to elements!")
      None
  }

  def getName(e: Elem): String =
    e.attributes.asAttrMap.get("rdf:about").map(s => splitCamelCase(OntModelUtils.removeNamespace(s))).getOrElse("")

  def splitCamelCase(s: String): String = StringUtils.splitByCharacterTypeCamelCase(s).mkString(" ")
}
