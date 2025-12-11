//go:build !windows

package windows

import (
	"context"

	"github.com/sjzar/chatlog/internal/wechat/model"
)

// Extract 从进程中提取密钥（非Windows平台实现）
// 返回：dataKey, imgKey, error
func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	return "", "", nil
}
