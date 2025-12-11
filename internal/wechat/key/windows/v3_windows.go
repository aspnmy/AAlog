package windows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"

	"github.com/aspnmy/chatlog/internal/errors"
	"github.com/aspnmy/chatlog/internal/wechat/model"
	"github.com/aspnmy/chatlog/pkg/util"
)

const (
	V3ModuleName = "WeChatWin.dll" // V3版本微信的主模块名称
	MaxWorkers   = 16              // 最大工作协程数
)

// Extract 从微信进程中提取V3版本密钥
// 参数：
//
//	ctx: 上下文，用于控制提取过程
//	proc: 微信进程信息
//
// 返回：
//
//	dataKey: 数据密钥
//	imgKey: 图片密钥（V3版本不返回图片密钥）
//	error: 错误信息
func (e *V3Extractor) Extract(ctx context.Context, proc *model.Process) (string, string, error) {
	if proc.Status == model.StatusOffline {
		return "", "", errors.ErrWeChatOffline
	}

	// 打开微信进程
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, proc.PID)
	if err != nil {
		return "", "", errors.OpenProcessFailed(err)
	}
	defer windows.CloseHandle(handle)

	// 检查进程架构
	is64Bit, err := util.Is64Bit(handle)
	if err != nil {
		return "", "", err
	}

	// 创建上下文以控制所有协程
	searchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 创建通道用于传递内存数据和结果
	memoryChannel := make(chan []byte, 100)
	resultChannel := make(chan string, 1)

	// 确定工作协程数量
	workerCount := runtime.NumCPU()
	if workerCount < 2 {
		workerCount = 2 // 至少2个协程
	}
	if workerCount > MaxWorkers {
		workerCount = MaxWorkers // 最多16个协程
	}
	log.Debug().Msgf("启动 %d 个工作协程进行 V3 密钥搜索", workerCount)

	// 启动消费者协程
	var workerWaitGroup sync.WaitGroup
	workerWaitGroup.Add(workerCount)
	for index := 0; index < workerCount; index++ {
		go func() {
			defer workerWaitGroup.Done()
			e.worker(searchCtx, handle, is64Bit, memoryChannel, resultChannel)
		}()
	}

	// 启动生产者协程
	var producerWaitGroup sync.WaitGroup
	producerWaitGroup.Add(1)
	go func() {
		defer producerWaitGroup.Done()
		defer close(memoryChannel) // 生产者完成后关闭通道
		err := e.findMemory(searchCtx, handle, proc.PID, memoryChannel)
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
	select {
	case <-ctx.Done():
		return "", "", ctx.Err()
	case result, ok := <-resultChannel:
		if ok && result != "" {
			return result, "", nil
		}
	}

	return "", "", errors.ErrNoValidKey
}

// findMemory 搜索WeChatWin.dll中的可写内存区域（V3版本）
// 参数：
//
//	ctx: 上下文，用于控制搜索过程
//	handle: 进程句柄
//	pid: 进程ID
//	memoryChannel: 用于传递内存数据的通道
//
// 返回：
//
//	error: 错误信息
func (e *V3Extractor) findMemory(ctx context.Context, handle windows.Handle, pid uint32, memoryChannel chan<- []byte) error {
	// 查找WeChatWin.dll模块
	module, isFound := FindModule(pid, V3ModuleName)
	if !isFound {
		return errors.ErrWeChatDLLNotFound
	}
	log.Debug().Msg("找到WeChatWin.dll模块，基地址: 0x" + fmt.Sprintf("%X", module.ModBaseAddr))

	// 读取可写内存区域
	baseAddr := uintptr(module.ModBaseAddr)
	endAddr := baseAddr + uintptr(module.ModBaseSize)
	currentAddr := baseAddr

	for currentAddr < endAddr {
		var mbi windows.MemoryBasicInformation
		err := windows.VirtualQueryEx(handle, currentAddr, &mbi, unsafe.Sizeof(mbi))
		if err != nil {
			break
		}

		// 跳过小内存区域
		if mbi.RegionSize < 100*1024 {
			currentAddr += uintptr(mbi.RegionSize)
			continue
		}

		// 检查内存区域是否可写
		isWritable := (mbi.Protect & (windows.PAGE_READWRITE | windows.PAGE_WRITECOPY | windows.PAGE_EXECUTE_READWRITE | windows.PAGE_EXECUTE_WRITECOPY)) > 0
		if isWritable && uint32(mbi.State) == windows.MEM_COMMIT {
			// 计算区域大小，确保不超出DLL边界
			regionSize := uintptr(mbi.RegionSize)
			if currentAddr+regionSize > endAddr {
				regionSize = endAddr - currentAddr
			}

			// 读取可写内存区域
			memory := make([]byte, regionSize)
			if err = windows.ReadProcessMemory(handle, currentAddr, &memory[0], regionSize, nil); err == nil {
				select {
				case memoryChannel <- memory:
					log.Debug().Msgf("内存区域: 0x%X - 0x%X, 大小: %d 字节", currentAddr, currentAddr+regionSize, regionSize)
				case <-ctx.Done():
					return nil
				}
			}
		}

		// 移动到下一个内存区域
		currentAddr = uintptr(mbi.BaseAddress) + uintptr(mbi.RegionSize)
	}

	return nil
}

// worker 处理内存区域以查找V3版本密钥
// 参数：
//
//	ctx: 上下文，用于控制工作协程
//	handle: 进程句柄
//	is64Bit: 进程是否为64位
//	memoryChannel: 用于接收内存数据的通道
//	resultChannel: 用于发送结果的通道
func (e *V3Extractor) worker(ctx context.Context, handle windows.Handle, is64Bit bool, memoryChannel <-chan []byte, resultChannel chan<- string) {
	// 定义搜索模式
	keyPattern := []byte{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	ptrSize := 8
	littleEndianFunc := binary.LittleEndian.Uint64

	// 调整为32位进程
	if !is64Bit {
		keyPattern = keyPattern[:4]
		ptrSize = 4
		littleEndianFunc = func(b []byte) uint64 { return uint64(binary.LittleEndian.Uint32(b)) }
	}

	for {
		select {
		case <-ctx.Done():
			return
		case memory, ok := <-memoryChannel:
			if !ok {
				return
			}

			index := len(memory)
			for {
				select {
				case <-ctx.Done():
					return // 如果上下文取消则退出
				default:
				}

				// 从末尾向前查找模式
				index = bytes.LastIndex(memory[:index], keyPattern)
				if index == -1 || index-ptrSize < 0 {
					break
				}

				// 提取并验证指针值
				ptrValue := littleEndianFunc(memory[index-ptrSize : index])
				if ptrValue > 0x10000 && ptrValue < 0x7FFFFFFFFFFF {
					if key := e.validateKey(handle, ptrValue); key != "" {
						select {
						case resultChannel <- key:
							log.Debug().Msg("找到有效密钥: " + key)
							return
						default:
						}
					}
				}
				index -= 1 // 从之前的位置继续搜索
			}
		}
	}
}

// validateKey 验证单个密钥候选
// 参数：
//
//	handle: 进程句柄
//	addr: 密钥在内存中的地址
//
// 返回：
//
//	string: 有效的密钥（如果验证成功）
func (e *V3Extractor) validateKey(handle windows.Handle, addr uint64) string {
	keyData := make([]byte, 0x20) // 32字节密钥
	if err := windows.ReadProcessMemory(handle, uintptr(addr), &keyData[0], uintptr(len(keyData)), nil); err != nil {
		return ""
	}

	// 根据数据库头验证密钥
	if e.validator.Validate(keyData) {
		return hex.EncodeToString(keyData)
	}

	return ""
}

// FindModule 在进程中搜索指定模块
// 参数：
//
//	pid: 进程ID
//	name: 模块名称
//
// 返回：
//
//	module: 模块信息
//	isFound: 是否找到模块
func FindModule(pid uint32, name string) (module windows.ModuleEntry32, isFound bool) {
	// 创建模块快照
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
	if err != nil {
		log.Debug().Msgf("为PID %d 创建模块快照失败: %v", pid, err)
		return module, false
	}
	defer windows.CloseHandle(snapshot)

	// 初始化模块条目结构
	module.Size = uint32(windows.SizeofModuleEntry32)

	// 获取第一个模块
	if err := windows.Module32First(snapshot, &module); err != nil {
		log.Debug().Msgf("为PID %d 获取第一个模块失败: %v", pid, err)
		return module, false
	}

	// 遍历所有模块查找WeChatWin.dll
	for ; err == nil; err = windows.Module32Next(snapshot, &module) {
		if windows.UTF16ToString(module.Module[:]) == name {
			return module, true
		}
	}
	return module, false
}
