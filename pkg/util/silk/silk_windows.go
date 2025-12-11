//go:build windows

package silk

import (
	"fmt"

	"github.com/aspnmy/go-lame-v1"
	"github.com/aspnmy/go-silk"
)

// Silk2MP3 将silk格式转换为mp3格式（Windows平台实现）
// 参数：
//
//	data: silk格式的音频数据
//
// 返回：
//
//	[]byte: mp3格式的音频数据
//	error: 错误信息
func Silk2MP3(data []byte) ([]byte, error) {
	sd := silk.SilkInit()
	defer sd.Close()

	pcmdata := sd.Decode(data)
	if len(pcmdata) == 0 {
		return nil, fmt.Errorf("silk decode failed")
	}

	le := lame.Init()
	defer le.Close()

	le.SetInSamplerate(24000)
	le.SetOutSamplerate(24000)
	le.SetNumChannels(1)
	le.SetBitrate(16)
	// IMPORTANT!
	le.InitParams()

	mp3data := le.Encode(pcmdata)
	if len(mp3data) == 0 {
		return nil, fmt.Errorf("mp3 encode failed")
	}

	return mp3data, nil
}
