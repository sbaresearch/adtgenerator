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

## Queries

SPARQL query to retrieve the processes, external entities or data stores that transfer data to the test management tool:

```
PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?sender ?flow
	WHERE { 
		?tmg rdf:type ?tmgType.
		?tmgType rdfs:subClassOf* ns:Process.
		?tmg rdfs:label "Test Management Tool"@en.
		?flow rdf:type ?flowType.
		?flowType rdfs:subClassOf* ns:DataFlow.
		{
			?ee rdf:type ?eeType.
			?eeType rdfs:subClassOf* ns:ExternalEntity.
			?flow ns:flows ?ee.
			BIND (?ee as ?sender)
		}
		UNION
		{
			?pr rdf:type ?prType.
			?prType rdfs:subClassOf* ns:Process.
			?flow ns:flows ?pr.
			BIND (?pr as ?sender)
		}
		UNION
		{
			?ds rdf:type ?dsType.
			?dsType rdfs:subClassOf* ns:DataStore.
			?flow ns:flows ?ds.
			BIND (?ds as ?sender)
		}.
		?flow ns:flows ?tmg.
		FILTER NOT EXISTS { ?sender rdfs:label "Test Management Tool"@en }
	}
```

SPARQL query to determine the attack targets for compromising test results:

```
PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?individual ?id
	WHERE { 
		?asset rdf:type ?assetType.
		?assetType rdfs:subClassOf* ns:Asset.
		?asset ns:usedBy ?individual.
		?individual ns:id ?id.
		?asset rdfs:label "Test Results"@en.
	}
```

SPARQL query to retrieve the roles that are accessing test results:

```
PREFIX ns: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?ee
	WHERE {
		?ee rdf:type ?eeType.
		?eeType rdfs:subClassOf* ns:ExternalEntity.
		?asset rdf:type ?assetType.
		?assetType rdfs:subClassOf* ns:Asset.
		?asset rdfs:label "Test Results"@en.
		?flow rdf:type ?flowType.
		?flowType rdfs:subClassOf* ns:DataFlow.
		?flow ns:flows ?ee.
		{
			?asset ns:usedBy ?flow
		}
		UNION
		{
			?flow ns:flows ?asset
		}
	}
```

SPARQL query to retrieve the STRIDE threats that put the test data at risk:

```
PREFIX dfd: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
PREFIX adt: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/ADT#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?threatType
	WHERE { 
		?asset rdf:type ?assetType.
		?assetType rdfs:subClassOf* dfd:Asset.
		?asset rdfs:label "Test Data"@en.
		?asset dfd:usedBy ?individual.
		?individual dfd:id ?id.
		?individual rdf:type ?individualType.
		?individualType rdfs:label ?individualTypeLabel.
		?goal rdf:type ?goalType.
		?goalType rdfs:subClassOf* adt:Goal.
		?goal adt:hasTarget ?targetType.
		?targetType rdfs:label ?targetTypeLabel.
		?goal adt:hasType ?threatType.
		FILTER(?individualTypeLabel = ?targetTypeLabel)
	}
GROUP BY ?threatType
```

SPARQL query to identify the most cost-effective countermeasures:

```
PREFIX dfd: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/DFD#>
PREFIX adt: <http://www.semanticweb.org/adtgenerator/ontologies/2018/10/ADT#>
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?countermeasure ?pCountermeasure ?cost ?attack ?pAttack
	WHERE { 
		?attack rdf:type ?attackType.
		?attackType rdfs:subClassOf* adt:AttackNode.
		?attack adt:connectedTo ?connector.
		?attack adt:successProbability ?pAttack.
		?countermeasure rdf:type ?countermeasureType.
		?countermeasureType rdfs:subClassOf* adt:DefenseNode.
		?connector adt:connectedTo ?countermeasure.
		?countermeasure adt:cost ?cost.
		?countermeasure adt:successProbability ?pCountermeasure
	}
ORDER BY DESC(?pAttack) ?pCountermeasure ?cost
```