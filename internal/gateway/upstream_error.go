package gateway

import "encoding/json"

// nativeErrorMetadata keeps only a bounded, allowlisted error type and status.
// Error messages, parameters and arbitrary upstream fields never enter logs.
func nativeErrorMetadata(data []byte) (int, string) {
	if len(data) > 8192 || validateUniqueJSONMembers(data) != nil {
		return 0, ""
	}
	var envelope struct {
		Error struct {
			Code int    `json:"code"`
			Type string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Error.Code < 400 || envelope.Error.Code > 599 {
		return 0, ""
	}
	switch envelope.Error.Type {
	case "Service Unavailable", "InternalServerError", "BadRequestError", "NotFoundError", "UnprocessableEntityError", "NotImplementedError":
		return envelope.Error.Code, envelope.Error.Type
	default:
		return 0, ""
	}
}
