package courier

import (
	"fmt"
	"net/http"
)

type MessageRejectedError struct {
	StatusCode   int
	ResponseBody string
}

func NewMessageRejectedError(statusCode int, responseBody string) error {
	return &MessageRejectedError{StatusCode: statusCode, ResponseBody: responseBody}
}
func (m *MessageRejectedError) Error() string {
	return fmt.Sprintf("Status: %s, body: %s", http.StatusText(m.StatusCode), m.ResponseBody)
}
