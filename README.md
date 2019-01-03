# ADTGenerator

ADTGenerator is a command-line tool that generates attack--defense trees (ADTrees) based on an ontological knowledge base which can be imported into [ADTool](http://satoss.uni.lu/members/piotr/adtool/). The imported ADTrees can then be used for threat modeling and risk assessment activities.

The knowledge base is composed of two ontologies, viz., DFD (`src/main/resources/DFD.owl`) and ADT (`src/main/resources/ADT.owl`). The DFD ontology can be used to model the target of inspection as a data flow diagram (DFD), whereas the ADT ontology models (generic) threat trees, which are based on ([Shostack, 2014](https://www.wiley.com/en-us/Threat+Modeling%3A+Designing+for+Security-p-9781118809990)), and specific threat scenarios.

Currently, ADTGenerator supports the generation of plain STRIDE threat trees that put a specific asset at risk and multi-stage sabotage ADTrees.

## Examples

Information disclosure (threat type) ADTree that targets the source code (asset): 

```
java -jar adtgenerator.jar --stride --threattype I --asset "Source Code"
```

Sabotage ADTree with the goal `Inject Malicious Code Into Source Code`:
```
java -jar adtgenerator.jar --sabotage --goal "Inject Malicious Code Into Source Code"
```