package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aspnmy/chatlog/internal/wechat/decrypt"
	"github.com/aspnmy/chatlog/internal/wechat/key/windows"
	"github.com/aspnmy/chatlog/internal/wechat/model"
)

func main() {
	// 初始化日志
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// 解析命令行参数
	pid := flag.Int("pid", 0, "微信进程PID")
	dataDir := flag.String("data-dir", ".", "微信数据目录路径")
	flag.Parse()

	if *pid == 0 {
		fmt.Println("请指定微信进程PID")
		fmt.Println("使用方法: v4getKey -pid <进程ID> -data-dir <微信数据目录>")
		fmt.Println("示例: v4getKey -pid 13676 -data-dir C:\\Users\\用户名\\Documents\\WeChat Files")
		os.Exit(1)
	}

	// 创建V4提取器
	extractor := windows.NewV4Extractor()

	// 创建验证器
	validator, err := decrypt.NewValidator("windows", 4, *dataDir)
	if err != nil {
		log.Err(err).Msgf("创建验证器失败，请确保指定的微信数据目录包含 db_storage\\message\\message_0.db 文件")
		fmt.Println("使用方法: v4getKey -pid <进程ID> -data-dir <微信数据目录>")
		fmt.Println("示例: v4getKey -pid 13676 -data-dir C:\\Users\\用户名\\Documents\\WeChat Files")
		os.Exit(1)
	}
	extractor.SetValidate(validator)

	// 创建进程信息
	proc := &model.Process{
		PID:    uint32(*pid),
		Status: model.StatusOnline,
	}

	// 提取密钥
	ctx := context.Background()
	dataKey, imgKey, err := extractor.Extract(ctx, proc)
	if err != nil {
		log.Err(err).Msg("提取密钥失败")
		os.Exit(1)
	}

	// 输出结果
	fmt.Println("=== Windows V4 微信密钥提取结果 ===")
	if dataKey != "" {
		fmt.Printf("数据密钥: %s\n", dataKey)
	}
	if imgKey != "" {
		fmt.Printf("图片密钥: %s\n", imgKey)
	}
	if dataKey == "" && imgKey == "" {
		fmt.Println("未找到有效密钥")
		os.Exit(1)
	}
}
