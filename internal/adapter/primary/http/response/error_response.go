package response

// ErrorResponse is the envelope returned by every endpoint when a request
// fails. Declaring it as a named type keeps the error contract explicit and
// lets the OpenAPI spec describe it as a JSON schema.
type ErrorResponse struct {
	Error string `json:"error"`
}
