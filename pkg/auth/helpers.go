package auth

import (
	"encoding/json"
	"os"
)

// Marshal - any given object into json
func Marshal(obj interface{}) ([]byte, error) {
	return json.Marshal(obj)
}

// Unmarshal from json any given object
func Unmarshal(bs []byte, obj interface{}) error {
	return json.Unmarshal(bs, obj)
}

func GetPublicKey() string {
	return os.Getenv(environmentVariablePublicKey)
}

func GetProjectID() string {
	return os.Getenv(environmentVariableProjectID)
}
