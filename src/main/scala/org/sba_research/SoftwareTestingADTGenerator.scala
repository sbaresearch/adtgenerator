package org.sba_research

import org.sba_research.model._
import scopt.OParser


object SoftwareTestingADTGenerator {

  def main(args: Array[String]): Unit = {

    val progName = "adtgenerator"
    val vers = "0.0.1"
    val builder = OParser.builder[CLIConfig]
    val parsr = {
      import builder._
      OParser.sequence(
        programName(progName),
        head(progName, vers),
        // --stride
        opt[Unit]("stride")
          .action((_, c) => c.copy(stride = true))
          .text("generates a plain STRIDE ADTree"),
        // -t --threattype <[STRIDE]>
        opt[Char]('t', "threattype")
          .action((x, c) => c.copy(threatType = Some(x)))
          .validate(x =>
            if (List('S', 'T', 'R', 'I', 'D', 'E').contains(x.toUpper)) success
            else failure("threat type must be S, T, R, I, D, or E")
          )
          .text("threat type must be S, T, R, I, D, or E"),
        // -a --asset <label>
        opt[String]('a', "asset")
          .action((x, c) => c.copy(asset = Some(x)))
          .text("asset name"),
        // --sabotage
        opt[Unit]("sabotage")
          .action((_, c) => c.copy(sabotage = true))
          .text("generates a sabotage ADTree"),
        // -g --goal <label>
        opt[String]('g', "goal")
          .action((x, c) => c.copy(goal = Some(x)))
          .text("goal name"),
        // --help
        help("help").text("prints this usage text"),
        checkConfig(c =>
          if (!c.stride && !c.sabotage) failure("either the plain STRIDE ADTree or sabotage ADTree flag must be set")
          else if (c.stride && c.sabotage) failure("only plain STRIDE or sabotage ADTree can be generated per run")
          else if (c.stride && (c.threatType.isEmpty || c.asset.isEmpty)) failure("the generation of a plain STRIDE ADTree requires the arguments threat type and asset")
          else if (c.sabotage && c.goal.isEmpty) failure("the generation of a sabotage ADTree requires the argument goal")
          else success
        )
      )
    }

    // OParser.parse returns Option[CliConfig]
    OParser.parse(parsr, args, CLIConfig()) match {
      case Some(cfg) =>
        // CLI args correct

        // Start initializing app config
        val config = Config()
        val ontModels = OntModels(config)

        val adt =
          if (cfg.stride) {
            for {
              t <- cfg.threatType
              a <- cfg.asset
            } yield ADTOntModelConverter.getPlainADT(config, ontModels, t, a)
          }
          else
            cfg.goal.map(g => ADTOntModelConverter.getSabotageADT(config, ontModels, g))

        adt match {
          case Some(tree) =>
            /// Marshalling: ADT -> XML
            tree.map(t => ADTXMLMarshaller.execute(config.outputPath, t))
          case _ =>
            System.err.println("Could not retrieve ADT because args have not been populated correctly.")
            System.exit(1)
        }

      case _ =>
        // Arguments are bad, print error message
        System.exit(1)
    }

  }


}