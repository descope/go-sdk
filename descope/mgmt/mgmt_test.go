package mgmt

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/descope/go-sdk/descope/utils"
)

func readBody(r *http.Request, m interface{}) (err error) {
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
		b, err := utils.Marshal(map[string]any{"error": errors.NewInvalidArgumentError("test")})
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

func newTestMgmt(clientParams *api.ClientParams, callback mocks.Do) *managementService {
	return newTestMgmtConf(nil, clientParams, callback)
}

func newTestMgmtConf(mgmtParams *MgmtParams, clientParams *api.ClientParams, callback mocks.Do) *managementService {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a"}
	}
	if mgmtParams == nil {
		mgmtParams = &MgmtParams{ProjectID: "a"}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewManagement(*mgmtParams, api.NewClient(*clientParams))
}
