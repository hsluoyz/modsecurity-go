package parser

var OperatorNameMap = map[int]string{}
var ActionNameMap = map[int]string{}
var TransformationNameMap = map[int]string{}
var VariableNameMap = map[int]string{}
var SeverityNameMap = map[int]string{}

func init() {
	for k, v := range operatorMap {
		OperatorNameMap[v] = k
	}

	for k, v := range actionMap {
		ActionNameMap[v] = k
	}

	for k, v := range transformationMap {
		TransformationNameMap[v] = k
	}

	for k, v := range variableMap {
		VariableNameMap[v] = k
	}

	for k, v := range severityMap {
		SeverityNameMap[v] = k
	}
}
