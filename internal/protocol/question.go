package protocol

type Question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}
