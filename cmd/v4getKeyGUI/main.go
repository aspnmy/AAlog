package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aspnmy/chatlog/internal/wechat/decrypt"
	"github.com/aspnmy/chatlog/internal/wechat/key/windows"
	"github.com/aspnmy/chatlog/internal/wechat/model"
	"github.com/shirou/gopsutil/v4/process"
)

func init() {
	// 初始化日志
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
}

func main() {
	fmt.Println("========================================")
	fmt.Println("微信V4密钥提取工具")
	fmt.Println("========================================")
	fmt.Println()

	// 1. 获取微信进程列表
	fmt.Println("1. 正在获取微信进程列表...")
	processes, err := getWeChatProcesses()
	if err != nil {
		fmt.Printf("错误: 获取进程列表失败 - %v\n", err)
		os.Exit(1)
	}

	if len(processes) == 0 {
		fmt.Println("错误: 未找到微信进程")
		os.Exit(1)
	}

	// 显示进程列表
	fmt.Println("微信进程列表:")
	for i, pid := range processes {
		fmt.Printf("  %d. PID: %s\n", i+1, pid)
	}

	// 2. 选择微信进程
	fmt.Println()
	fmt.Print("请选择微信进程 (输入编号): ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("错误: 读取输入失败 - %v\n", err)
		os.Exit(1)
	}

	// 解析输入
	selection, err := strconv.Atoi(input[:len(input)-1])
	if err != nil || selection < 1 || selection > len(processes) {
		fmt.Println("错误: 无效的选择")
		os.Exit(1)
	}

	// 获取选中的PID
	pidStr := processes[selection-1]
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		fmt.Printf("错误: 无效的PID - %v\n", err)
		os.Exit(1)
	}

	// 3. 获取微信数据目录
	fmt.Println()
	fmt.Print("请输入微信数据目录 (默认为当前目录): ")
	dataDirInput, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("错误: 读取输入失败 - %v\n", err)
		os.Exit(1)
	}

	// 处理输入
	dataDir := dataDirInput[:len(dataDirInput)-1]
	if dataDir == "" {
		dataDir = "."
	}

	// 检查目录是否存在
	if _, statErr := os.Stat(dataDir); os.IsNotExist(statErr) {
		fmt.Printf("错误: 目录不存在 - %s\n", dataDir)
		os.Exit(1)
	}

	// 检查是否包含所需文件
	requiredFile := filepath.Join(dataDir, "db_storage", "message", "message_0.db")
	if _, statErr := os.Stat(requiredFile); os.IsNotExist(statErr) {
		fmt.Printf("警告: 未找到所需文件 - %s\n", requiredFile)
		fmt.Printf("请确保 %s 是正确的微信数据目录\n", dataDir)
	}

	// 4. 提取密钥
	fmt.Println()
	fmt.Println("正在提取密钥...")
	fmt.Println("这可能需要一些时间，请稍候...")
	fmt.Println()

	// 创建V4提取器
	extractor := windows.NewV4Extractor()

	// 创建验证器
	validator, err := decrypt.NewValidator("windows", 4, dataDir)
	if err != nil {
		fmt.Printf("错误: 创建验证器失败 - %v\n", err)
		os.Exit(1)
	}
	extractor.SetValidate(validator)

	// 创建进程信息
	proc := &model.Process{
		PID:    uint32(pid),
		Status: model.StatusOnline,
	}

	// 提取密钥
	ctx := context.Background()
	dataKey, imgKey, err := extractor.Extract(ctx, proc)
	if err != nil {
		fmt.Printf("错误: 提取密钥失败 - %v\n", err)
		os.Exit(1)
	}

	// 5. 显示结果
	fmt.Println("========================================")
	fmt.Println("提取结果:")
	fmt.Println("========================================")

	if dataKey != "" {
		fmt.Printf("数据密钥: %s\n", dataKey)
	}

	if imgKey != "" {
		fmt.Printf("图片密钥: %s\n", imgKey)
	}

	if dataKey == "" && imgKey == "" {
		fmt.Println("未找到有效密钥")
	} else {
		fmt.Println()
		fmt.Println("密钥提取成功!")
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("按回车键退出...")
	reader.ReadString('\n')
}

// getWeChatProcesses 获取微信进程列表
func getWeChatProcesses() ([]string, error) {
	// 获取所有进程
	processes, err := process.Processes()
	if err != nil {
		return nil, err
	}

	// 过滤微信进程
	var wechatProcesses []string
	for _, p := range processes {
		name, err := p.Name()
		if err != nil {
			continue
		}

		// 判断是否是微信进程
		if name == "WeChat.exe" {
			pid := p.Pid
			wechatProcesses = append(wechatProcesses, fmt.Sprintf("%d", pid))
		}
	}

	return wechatProcesses, nil
}
