package windows

import (
	"context"

	"github.com/aspnmy/chatlog/internal/wechat/decrypt"
)

type V3Extractor struct {
	validator *decrypt.Validator
}

func NewV3Extractor() *V3Extractor {
	return &V3Extractor{}
}

func (e *V3Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// TODO: 实现V3版本的密钥搜索逻辑
	return "", false
}

func (e *V3Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}
