package helpers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/mocks"
)

func ReadBody(r *http.Request, m any) (err error) {
	reader, err := r.GetBody()
	if err != nil {
		return err
	}
	res, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, &m)
	return
}

func ReadParams(r *http.Request) (params map[string]string) {
	params = map[string]string{}
	values := r.URL.Query()
	for key, val := range values {
		params[key] = val[0]
	}
	return
}

func DoOk(checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString("{}"))}
		return res, nil
	}
}

func DoBadRequest(checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		b, err := utils.Marshal(map[string]any{"foo": "bar"})
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoOkWithBody(checks func(*http.Request), body any) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}

		b, err := utils.Marshal(body)
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}
