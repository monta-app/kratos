package code

import (
	"crypto/rand"
	"io"
)

//go:generate mockgen -destination=mocks/mock_code_generator.go -package=mocks github.com/ory/kratos/selfservice/strategy/code RandomCodeGenerator

type RandomCodeGenerator interface {
	Generate(max int) string
}

type randomCodeGeneratorImpl struct{}

type RandomCodeGeneratorProvider interface {
	RandomCodeGenerator() RandomCodeGenerator
}

func NewRandomCodeGenerator() RandomCodeGenerator {
	return &randomCodeGeneratorImpl{}
}

var table = [...]byte{'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'}

func (s *randomCodeGeneratorImpl) Generate(max int) string {
	b := make([]byte, max)
	n, err := io.ReadAtLeast(rand.Reader, b, max)
	if err != nil || n != max {
		panic(err)
	}
	for i := 0; i < len(b); i++ {
		b[i] = table[int(b[i])%len(table)]
	}
	return string(b)
}
