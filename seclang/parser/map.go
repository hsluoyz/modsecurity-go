package parser

var OperatorNameMap = map[int]string{}
var ActionNameMap = map[int]string{}
var TransformationNameMap = map[int]string{}
var VariableNameMap = map[int]string{}
var SeverityNameMap = map[int]string{}

func init() {
	for k, v := range OperatorMap {
		OperatorNameMap[v] = k
	}

	for k, v := range ActionMap {
		ActionNameMap[v] = k
	}

	for k, v := range TransformationMap {
		TransformationNameMap[v] = k
	}

	for k, v := range VariableMap {
		VariableNameMap[v] = k
	}

	for k, v := range SeverityMap {
		SeverityNameMap[v] = k
	}
}
