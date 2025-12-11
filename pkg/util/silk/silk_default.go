//go:build !windows

package silk

import (
	"fmt"
)

// Silk2MP3 将silk格式转换为mp3格式
// 参数：
//
//	data: silk格式的音频数据
//
// 返回：
//
//	[]byte: mp3格式的音频数据
//	error: 错误信息
func Silk2MP3(data []byte) ([]byte, error) {
	// 默认实现，不支持任何平台
	return nil, fmt.Errorf("silk2mp3 not supported on this platform")
}
