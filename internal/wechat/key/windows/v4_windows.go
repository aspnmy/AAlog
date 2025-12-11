package windows

import (
	"context"
	"encoding/hex"
	"runtime"
	"sync"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/aspnmy/chatlog/internal/errors"
	"github.com/aspnmy/chatlog/internal/wechat/model"
)

const (
	MEM_PRIVATE = 0x20000 // 私有内存类型
)

// Extract 从微信进程中提取V4版本密钥
// 参数：
//
//	ctx: 上下文，用于控制提取过程
//	proc: 微信进程信息
//
// 返回：
//
//	dataKey: 数据密钥
//	imgKey: 图片密钥
//	error: 错误信息
func (e *V4Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	if proc.Status == model.StatusOffline {
		return "", "", errors.ErrWeChatOffline
	}

	// 打开进程句柄
	handle, err := windows.OpenProcess(windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, false, proc.PID)
	if err != nil {
		return "", "", errors.OpenProcessFailed(err)
	}
	defer windows.CloseHandle(handle)

	// 创建上下文以控制所有协程
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 创建通道用于传递内存数据和结果
	memoryChannel := make(chan []byte, 100)
	resultChannel := make(chan [2]string, 1)

	// 确定工作协程数量
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2 // 至少2个协程
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers // 最多16个协程
	}
	log.Debug().Msgf("启动 %d 个工作协程进行 V4 密钥搜索", workerCount)

	// 启动消费者协程
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			e.worker(searchCtx, handle, memoryChannel, resultChannel)
		}()
	}

	// 启动生产者协程
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // 生产者完成后关闭通道
		err := e.findMemory(searchCtx, handle, memoryChannel)
		if err != nil {
			log.Err(err).Msg("查找内存区域失败")
		}
	}()

	// 等待生产者和消费者完成
	go func() {
		producerWaitGroup.Wait()
		workerWaitGroup.Wait()
		close(resultChannel)
	}()

	// 等待结果
	var finalDataKey, finalImgKey string

	for {
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case result, ok := <-resultChannel:
			if !ok {
				// 通道关闭，所有工作协程完成，返回找到的任何密钥
				if finalDataKey != "" || finalImgKey != "" {
					return finalDataKey, finalImgKey, nil
				}
				return "", "", errors.ErrNoValidKey
			}

			// 更新我们找到的最佳密钥
			if result[0] != "" {
				finalDataKey = result[0]
			}
			if result[1] != "" {
				finalImgKey = result[1]
			}

			// 如果我们有两个密钥，可以提前返回
			if finalDataKey != "" && finalImgKey != "" {
				cancel() // 取消剩余工作
				return finalDataKey, finalImgKey, nil
			}
		}
	}
}

// findMemory 搜索可写内存区域（V4版本）
// 参数：
//
//	ctx: 上下文，用于控制搜索过程
//	handle: 进程句柄
//	memoryChannel: 用于传递内存数据的通道
//
// 返回：
//
//	error: 错误信息
func (e *V4Extractor) findMemory(ctx context.Context, handle windows.Handle, memoryChannel chan<- []byte) error {
	// 定义搜索范围
	minAddr := uintptr(0x10000)    // 进程空间通常从0x10000开始
	maxAddr := uintptr(0x7FFFFFFF) // 32位进程空间限制

	if runtime.GOARCH == "amd64" {
		maxAddr = uintptr(0x7FFFFFFFFFFF) // 64位进程空间限制
	}
	log.Info().Msgf("开始扫描内存区域从 0x%X 到 0x%X", minAddr, maxAddr)

	currentAddr := minAddr
	regionCount := 0

	for currentAddr < maxAddr {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		var memInfo windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(handle, currentAddr, &memInfo, unsafe.Sizeof(memInfo))
		if err != nil {
			break
		}

		// 跳过小内存区域
		if memInfo.RegionSize < 1024*1024 {
			currentAddr += uintptr(memInfo.RegionSize)
			continue
		}

		// 检查内存区域是否可读且私有
		if memInfo.State == windows.MEM_COMMIT && (memInfo.Protect&windows.PAGE_READWRITE) != 0 && memInfo.Type == MEM_PRIVATE {
			// 计算区域大小，确保不超出限制
			regionSize := uintptr(memInfo.RegionSize)
			if currentAddr+regionSize > maxAddr {
				regionSize = maxAddr - currentAddr
			}

			// 读取内存区域
			memory := make([]byte, regionSize)
			if err = windows.ReadProcessMemory(handle, currentAddr, &memory[0], regionSize, nil); err == nil {
				select {
				case memoryChannel <- memory:
					regionCount++
					// 每处理10个区域记录一次日志，避免过多日志输出
					if regionCount%10 == 0 {
						log.Info().Msgf("已处理 %d 个内存区域", regionCount)
					}
				case <-ctx.Done():
					return nil
				}
			}
		}

		// 移动到下一个内存区域
		currentAddr = uintptr(memInfo.BaseAddress) + uintptr(memInfo.RegionSize)
	}

	log.Info().Msgf("内存扫描完成，共处理 %d 个内存区域", regionCount)
	return nil
}

// worker 处理内存区域以查找V4版本密钥
// 参数：
//
//	ctx: 上下文，用于控制工作协程
//	handle: 进程句柄
//	memoryChannel: 用于接收内存数据的通道
//	resultChannel: 用于发送结果的通道
func (e *V4Extractor) worker(ctx context.Context, handle windows.Handle, memoryChannel <-chan []byte, resultChannel chan<- [2]string) {
	// 跟踪找到的密钥
	var dataKey, imgKey string

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				// 内存扫描完成，返回找到的任何密钥
				if dataKey != "" || imgKey != "" {
					select {
					case resultChannel <- [2]string{dataKey, imgKey}:
					default:
					}
				}
				return
			}

			// 检查是否已经找到两个密钥，如果是则跳过处理
			select {
			case <-ctx.Done():
				return
			default:
			}

			// 使用SearchKey方法搜索密钥（该方法会并行执行所有搜索策略）
			if key, found := e.SearchKey(ctx, memory); found {
				// 验证密钥类型
				keyData, err := hex.DecodeString(key)
				if err == nil {
					// 检查是数据密钥还是图片密钥
					if len(keyData) == 32 && e.validator.Validate(keyData) {
						if dataKey == "" {
							dataKey = key
							log.Info().Msg("找到数据密钥")
							// 找到后立即报告
							select {
							case resultChannel <- [2]string{dataKey, imgKey}:
							case <-ctx.Done():
								return
							}
						}
					} else if len(keyData) == 16 && e.validator.ValidateImgKey(keyData) {
						if imgKey == "" {
							imgKey = key
							log.Info().Msg("找到图片密钥")
							// 找到后立即报告
							select {
							case resultChannel <- [2]string{dataKey, imgKey}:
							case <-ctx.Done():
								return
							}
						}
					} else if len(keyData) == 32 && e.validator.ValidateImgKey(keyData) {
						if imgKey == "" {
							imgKey = key[:32] // 图片密钥只需要前16字节
							log.Info().Msg("找到图片密钥")
							// 找到后立即报告
							select {
							case resultChannel <- [2]string{dataKey, imgKey}:
							case <-ctx.Done():
								return
							}
						}
					}

					// 如果我们有两个密钥，退出工作协程
					if dataKey != "" && imgKey != "" {
						log.Info().Msg("找到两个密钥，工作协程退出")
						return
					}
				}
			}
		}
	}
}

// validateKey 验证单个密钥候选并返回密钥以及它是否是图片密钥
// 参数：
//
//	handle: 进程句柄
//	addr: 密钥在内存中的地址
//
// 返回：
//
//	string: 有效的密钥（如果验证成功）
//	bool: 是否是图片密钥
func (e *V4Extractor) validateKey(handle windows.Handle, addr uint64) (string, bool) {
	keyData := make([]byte, 0x20) // 32字节密钥
	if err := windows.ReadProcessMemory(handle, uintptr(addr), &keyData[0], uintptr(len(keyData)), nil); err != nil {
		return "", false
	}

	// 首先检查它是否是有效的数据库密钥
	if e.validator.Validate(keyData) {
		return hex.EncodeToString(keyData), false // 数据密钥
	}

	// 然后检查它是否是有效的图片密钥
	if e.validator.ValidateImgKey(keyData) {
		return hex.EncodeToString(keyData[:16]), true // 图片密钥
	}

	return "", false
}
