package org.sba_research

case class CLIConfig(
                      stride: Boolean = false,
                      threatType: Option[Char] = None,
                      asset: Option[String] = None,
                      sabotage: Boolean = false,
                      goal: Option[String] = None
                    )
