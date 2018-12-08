package org.sba_research

import org.apache.jena.util.SplitIRI

object OntModelUtils {

  /**
    * Removes the namespace from a given String.
    *
    * @param s the String to remove the namespace from
    * @return a string without the namespace
    */
  def removeNamespace(s: String): String = SplitIRI.splitpoint(s) match {
    case x if x > -1 => s.substring(x)
    case _ => s
  }

}
