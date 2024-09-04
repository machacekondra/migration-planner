// Package v1alpha1 provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package v1alpha1

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

// Base64 encoded, gzipped, json marshaled Swagger object
var swaggerSpec = []string{

	"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",
}

// GetSwagger returns the content of the embedded swagger specification file
// or error if failed to decode
func decodeSpec() ([]byte, error) {
	zipped, err := base64.StdEncoding.DecodeString(strings.Join(swaggerSpec, ""))
	if err != nil {
		return nil, fmt.Errorf("error base64 decoding spec: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(zipped))
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}
	var buf bytes.Buffer
	_, err = buf.ReadFrom(zr)
	if err != nil {
		return nil, fmt.Errorf("error decompressing spec: %w", err)
	}

	return buf.Bytes(), nil
}

var rawSpec = decodeSpecCached()

// a naive cached of a decoded swagger spec
func decodeSpecCached() func() ([]byte, error) {
	data, err := decodeSpec()
	return func() ([]byte, error) {
		return data, err
	}
}

// Constructs a synthetic filesystem for resolving external references when loading openapi specifications.
func PathToRawSpec(pathToFile string) map[string]func() ([]byte, error) {
	res := make(map[string]func() ([]byte, error))
	if len(pathToFile) > 0 {
		res[pathToFile] = rawSpec
	}

	return res
}

// GetSwagger returns the Swagger specification corresponding to the generated code
// in this file. The external references of Swagger specification are resolved.
// The logic of resolving external references is tightly connected to "import-mapping" feature.
// Externally referenced files must be embedded in the corresponding golang packages.
// Urls can be supported but this task was out of the scope.
func GetSwagger() (swagger *openapi3.T, err error) {
	resolvePath := PathToRawSpec("")

	loader := openapi3.NewLoader()
	loader.IsExternalRefsAllowed = true
	loader.ReadFromURIFunc = func(loader *openapi3.Loader, url *url.URL) ([]byte, error) {
		pathToFile := url.String()
		pathToFile = path.Clean(pathToFile)
		getSpec, ok := resolvePath[pathToFile]
		if !ok {
			err1 := fmt.Errorf("path not found: %s", pathToFile)
			return nil, err1
		}
		return getSpec()
	}
	var specData []byte
	specData, err = rawSpec()
	if err != nil {
		return
	}
	swagger, err = loader.LoadFromData(specData)
	if err != nil {
		return
	}
	return
}
