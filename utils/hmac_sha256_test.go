package utils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenerateSha256(t *testing.T) {
	ast := assert.New(t)
	ast.Equal("2dce505d96a53c5768052ee90f3df2055657518dad489160df9913f66042e160",
		GenerateSha256("mysecret", "data"),
	)
}
