package utils

import (
	"encoding/json"
	"os"
	"time"

	"github.com/descope/go-sdk/descope/logger"
)

// Marshal - any given object into json
func Marshal(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// Unmarshal from json any given object
func Unmarshal(bs []byte, obj interface{}) error {
	return json.Unmarshal(bs, obj)
}

func GetPublicKeyEnvVariable() string {
	return os.Getenv(EnvironmentVariablePublicKey)
}

func GetProjectIDEnvVariable() string {
	return os.Getenv(EnvironmentVariableProjectID)
}

func RunWithRetries(retriesCount, retryInterval int, logAction string, f func() error) error {
	var err error
	for i := retriesCount; i > 0; i-- {
		err = f()
		if err != nil && i > 1 {
			logger.LogInfo("failed action [%s], retrying. retries left: %d", logAction, i-1)
			time.Sleep(time.Second * time.Duration(retryInterval))
			continue
		}
		break
	}
	return err
}
