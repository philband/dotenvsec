package redact

import "fmt"

type Error struct {
	Code string
	Err  error
}

func (e Error) Error() string {
	if e.Err == nil {
		return e.Code
	}
	return fmt.Sprintf("%s: %v", e.Code, e.Err)
}
func (e Error) Unwrap() error { return e.Err }

func New(code string, err error) error { return Error{Code: code, Err: err} }
