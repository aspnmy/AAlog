package windows

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"

	"github.com/aspnmy/chatlog/internal/wechat/decrypt"
)

// SearchStrategy 定义密钥搜索策略接口
type SearchStrategy interface {
	// Name 返回策略名称
	Name() string
	// Search 在内存中搜索密钥
	Search(ctx context.Context, memory []byte, validator *decrypt.Validator) (string, bool)
}

// BasePatternSearch 基础模式搜索策略
type BasePatternSearch struct{}

func (s *BasePatternSearch) Name() string {
	return "base_pattern"
}

func (s *BasePatternSearch) Search(ctx context.Context, memory []byte, validator *decrypt.Validator) (string, bool) {
	// 定义搜索模式（V4版本）
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	ptrSize := 8
	littleEndianFunc := binary.LittleEndian.Uint64

	index := len(memory)
	for {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}

		// 从末尾向前查找模式
		index = bytes.LastIndex(memory[:index], keyPattern)
		if index == -1 || index-ptrSize < 0 {
			break
		}

		// 提取密钥指针
		ptrOffset := int(littleEndianFunc(memory[index-ptrSize : index]))

		// 检查指针偏移量是否在有效范围内
		if ptrOffset > 0x10000 && ptrOffset < len(memory)-0x20 {
			// 从内存中提取密钥数据
			keyData := memory[ptrOffset : ptrOffset+0x20]

			// 验证密钥
			if validator != nil {
				if validator.Validate(keyData) {
					return hex.EncodeToString(keyData), true
				} else if validator.ValidateImgKey(keyData) {
					return hex.EncodeToString(keyData[:16]), true
				}
			} else {
				// 没有验证器时，直接返回找到的密钥（用于测试）
				return hex.EncodeToString(keyData), true
			}
		}
		index -= len(keyPattern) // 优化：跳过整个模式，避免重复检查
	}

	return "", false
}

// SetDBKeyLogSearch 基于SetDBKey日志的搜索策略
type SetDBKeyLogSearch struct{}

func (s *SetDBKeyLogSearch) Name() string {
	return "setdbkey_log"
}

func (s *SetDBKeyLogSearch) Search(ctx context.Context, memory []byte, validator *decrypt.Validator) (string, bool) {
	// 搜索SetDBKey相关的日志特征
	setDBKeyPattern := []byte("SetDBKey")
	index := 0

	for {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}

		// 查找SetDBKey字符串
		index = bytes.Index(memory[index:], setDBKeyPattern)
		if index == -1 {
			break
		}

		// 调整索引到SetDBKey字符串的实际位置
		actualIndex := index
		index += len(setDBKeyPattern)

		// 方法1：搜索SetDBKey函数调用，第二个参数是密钥指针
		// 在SetDBKey字符串前后查找函数调用模式
		searchRange := 200 // 搜索范围：SetDBKey前后200字节
		start := actualIndex - searchRange
		if start < 0 {
			start = 0
		}
		end := index + searchRange
		if end > len(memory) {
			end = len(memory)
		}

		// 查找函数调用模式（基于x86/x64调用约定）
		if key, found := s.findSetDBKeyCall(memory[start:end], memory, validator); found {
			return key, true
		}

		// 方法2：在SetDBKey附近直接搜索密钥数据
		if key, found := s.findKeyInRange(memory[start:end], validator); found {
			return key, true
		}
	}

	return "", false
}

// findSetDBKeyCall 查找SetDBKey函数调用，提取第二个参数作为密钥指针
func (s *SetDBKeyLogSearch) findSetDBKeyCall(localMemory, fullMemory []byte, validator *decrypt.Validator) (string, bool) {
	// 搜索可能的函数调用模式
	// 在x64调用约定中，第二个参数通常通过rdx寄存器传递
	// 我们搜索可能的密钥指针模式

	// 查找32字节密钥数据
	for i := 0; i < len(localMemory)-32; i++ {
		keyData := localMemory[i : i+32]

		// 检查是否是有效的密钥
		if validator != nil {
			if validator.Validate(keyData) {
				return hex.EncodeToString(keyData), true
			} else if validator.ValidateImgKey(keyData) {
				return hex.EncodeToString(keyData[:16]), true
			}
		} else if s.isValidKeyPattern(keyData) {
			return hex.EncodeToString(keyData), true
		}
	}

	// 查找可能的密钥指针（8字节地址）
	for i := 0; i < len(localMemory)-8; i++ {
		// 提取可能的指针值
		ptrValue := binary.LittleEndian.Uint64(localMemory[i : i+8])

		// 检查指针是否指向有效内存范围
		if ptrValue > 0x10000 && ptrValue < uint64(len(fullMemory))-32 {
			// 从指针位置提取密钥数据
			keyData := fullMemory[ptrValue : ptrValue+32]

			// 验证密钥
			if validator != nil {
				if validator.Validate(keyData) {
					return hex.EncodeToString(keyData), true
				} else if validator.ValidateImgKey(keyData) {
					return hex.EncodeToString(keyData[:16]), true
				}
			} else if s.isValidKeyPattern(keyData) {
				return hex.EncodeToString(keyData), true
			}
		}
	}

	return "", false
}

func (s *SetDBKeyLogSearch) findKeyInRange(memory []byte, validator *decrypt.Validator) (string, bool) {
	// 在给定范围内查找可能的密钥
	// 查找32字节的连续数据，可能是密钥
	for i := 0; i < len(memory)-32; i++ {
		// 提取可能的密钥数据
		keyData := memory[i : i+32]

		// 验证密钥
		if validator != nil {
			if validator.Validate(keyData) {
				return hex.EncodeToString(keyData), true
			} else if validator.ValidateImgKey(keyData) {
				return hex.EncodeToString(keyData[:16]), true
			}
		} else {
			// 没有验证器时，检查数据是否符合密钥特征
			if s.isValidKeyPattern(keyData) {
				return hex.EncodeToString(keyData), true
			}
		}
	}

	return "", false
}

func (s *SetDBKeyLogSearch) isValidKeyPattern(data []byte) bool {
	// 检查数据是否符合密钥特征
	// 简单检查：数据不能全为0或全为同一值
	allZero := true
	allSame := true
	firstByte := data[0]

	for _, b := range data {
		if b != 0 {
			allZero = false
		}
		if b != firstByte {
			allSame = false
		}
		if !allZero && !allSame {
			break
		}
	}

	return !allZero && !allSame
}

// SQLiteSafetySearch 基于sqlite3SafetyCheckOk的搜索策略
type SQLiteSafetySearch struct{}

func (s *SQLiteSafetySearch) Name() string {
	return "sqlite_safety"
}

func (s *SQLiteSafetySearch) Search(ctx context.Context, memory []byte, validator *decrypt.Validator) (string, bool) {
	// 根据CSDN文章，微信4.1+版本中，"unopened"字符串用于定位sqlite3SafetyCheckOk函数
	// 该函数由sqlite3_exec等函数调用，而这些函数与setCipherKey相关
	unopenedPattern := []byte("unopened")
	index := 0

	for {
		select {
		case <-ctx.Done():
			return "", false
		default:
		}

		// 查找"unopened"字符串
		index = bytes.Index(memory[index:], unopenedPattern)
		if index == -1 {
			break
		}

		// 调整索引到"unopened"字符串的实际位置
		actualIndex := index
		index += len(unopenedPattern)

		// sqlite3SafetyCheckOk函数附近应该有sqlite3相关函数
		// 扩大搜索范围以找到更多相关函数
		searchRange := 1000 // 搜索范围："unopened"前后1000字节
		start := actualIndex - searchRange
		if start < 0 {
			start = 0
		}
		end := index + searchRange
		if end > len(memory) {
			end = len(memory)
		}

		// 搜索sqlite3相关函数和密钥
		if key, found := s.searchSQLiteRelatedFunctions(memory[start:end], memory, validator); found {
			return key, true
		}
	}

	return "", false
}

func (s *SQLiteSafetySearch) searchSQLiteRelatedFunctions(localMemory, fullMemory []byte, validator *decrypt.Validator) (string, bool) {
	// 根据CSDN文章，我们需要查找sqlite3相关函数
	// 如sqlite3_exec, sqlite3_prepare_v2等，这些函数与setCipherKey相关
	sqlitePatterns := [][]byte{
		[]byte("sqlite3_exec"),
		[]byte("sqlite3_prepare_v2"),
		[]byte("sqlite3_prepare"),
		[]byte("sqlite3_step"),
		[]byte("setCipherKey"), // 直接搜索setCipherKey
		[]byte("WCDB"),         // 微信数据库框架
	}

	for _, pattern := range sqlitePatterns {
		index := 0
		for {
			index = bytes.Index(localMemory[index:], pattern)
			if index == -1 {
				break
			}

			// 调整索引到模式的实际位置
			patternStart := index
			index += len(pattern)

			// 搜索该sqlite函数附近的密钥数据
			if key, found := s.searchForKeyAroundSQLiteFunction(localMemory, patternStart, fullMemory, validator); found {
				return key, true
			}
		}
	}

	return "", false
}

func (s *SQLiteSafetySearch) searchForKeyAroundSQLiteFunction(localMemory []byte, patternStart int, fullMemory []byte, validator *decrypt.Validator) (string, bool) {
	// 搜索sqlite函数附近的密钥数据
	// 1. 首先检查直接密钥数据
	// 2. 然后检查密钥指针

	// 搜索范围：函数前后500字节
	searchRange := 500
	start := patternStart - searchRange
	if start < 0 {
		start = 0
	}
	end := patternStart + searchRange
	if end > len(localMemory) {
		end = len(localMemory)
	}

	searchArea := localMemory[start:end]

	// 方法1：直接搜索32字节密钥数据
	for i := 0; i < len(searchArea)-32; i++ {
		keyData := searchArea[i : i+32]

		// 验证密钥
		if validator != nil {
			if validator.Validate(keyData) {
				return hex.EncodeToString(keyData), true
			} else if validator.ValidateImgKey(keyData) {
				return hex.EncodeToString(keyData[:16]), true
			}
		} else if s.isValidKeyPattern(keyData) {
			return hex.EncodeToString(keyData), true
		}
	}

	// 方法2：搜索密钥指针（8字节地址）
	for i := 0; i < len(searchArea)-8; i++ {
		// 提取可能的指针值
		ptrValue := binary.LittleEndian.Uint64(searchArea[i : i+8])

		// 检查指针是否指向有效内存范围
		if ptrValue > 0x10000 && ptrValue < uint64(len(fullMemory))-32 {
			// 从指针位置提取密钥数据
			keyData := fullMemory[ptrValue : ptrValue+32]

			// 验证密钥
			if validator != nil {
				if validator.Validate(keyData) {
					return hex.EncodeToString(keyData), true
				} else if validator.ValidateImgKey(keyData) {
					return hex.EncodeToString(keyData[:16]), true
				}
			} else if s.isValidKeyPattern(keyData) {
				return hex.EncodeToString(keyData), true
			}
		}
	}

	return "", false
}

func (s *SQLiteSafetySearch) isValidKeyPattern(data []byte) bool {
	// 检查数据是否符合密钥特征
	// 密钥应该是随机的，不应该全为0或有明显的规律
	allZero := true
	allSame := true
	firstByte := data[0]

	for _, b := range data {
		if b != 0 {
			allZero = false
		}
		if b != firstByte {
			allSame = false
		}
		if !allZero && !allSame {
			break
		}
	}

	return !allZero && !allSame
}

type V4Extractor struct {
	validator  *decrypt.Validator
	strategies []SearchStrategy
}

func NewV4Extractor() *V4Extractor {
	// 初始化默认搜索策略
	strategies := []SearchStrategy{
		&BasePatternSearch{},
		&SetDBKeyLogSearch{},
		&SQLiteSafetySearch{},
		&WeixinDLLSearch{}, // 微信4.1+版本的Weixin.dll搜索策略
	}

	return &V4Extractor{
		strategies: strategies,
	}
}

func (e *V4Extractor) SearchKey(ctx context.Context, memory []byte) (string, bool) {
	// 并行执行所有搜索策略
	resultChan := make(chan struct {
		key      string
		found    bool
		strategy string
	}, len(e.strategies))

	// 启动所有搜索策略
	for _, strategy := range e.strategies {
		go func(s SearchStrategy) {
			key, found := s.Search(ctx, memory, e.validator)
			resultChan <- struct {
				key      string
				found    bool
				strategy string
			}{key, found, s.Name()}
		}(strategy)
	}

	// 收集搜索结果
	for i := 0; i < len(e.strategies); i++ {
		result := <-resultChan
		if result.found {
			return result.key, true
		}
	}

	return "", false
}

func (e *V4Extractor) SetValidate(validator *decrypt.Validator) {
	e.validator = validator
}

// WeixinDLLSearch 针对Weixin.dll的搜索策略（微信4.1+版本）
type WeixinDLLSearch struct{}

func (s *WeixinDLLSearch) Name() string {
	return "weixin_dll"
}

func (s *WeixinDLLSearch) Search(ctx context.Context, memory []byte, validator *decrypt.Validator) (string, bool) {
	// 微信4.1+版本使用Weixin.dll替代了WeChatWin.dll
	// 搜索Weixin.dll相关的特征
	weixinDLLPatterns := [][]byte{
		[]byte("Weixin.dll"),
		[]byte("xwechat_files"), // 新的数据存储位置
		[]byte("db_storage"),    // 数据库存储目录
	}

	for _, pattern := range weixinDLLPatterns {
		index := 0
		for {
			select {
			case <-ctx.Done():
				return "", false
			default:
			}

			// 查找模式
			index = bytes.Index(memory[index:], pattern)
			if index == -1 {
				break
			}

			// 调整索引
			index += len(pattern)

			// 搜索附近的密钥
			searchRange := 500 // 搜索范围：模式前后500字节
			start := index - searchRange
			if start < 0 {
				start = 0
			}
			end := index + searchRange
			if end > len(memory) {
				end = len(memory)
			}

			// 在搜索范围内查找密钥
			if key, found := s.findKeyInRange(memory[start:end], validator); found {
				return key, true
			}
		}
	}

	return "", false
}

func (s *WeixinDLLSearch) findKeyInRange(memory []byte, validator *decrypt.Validator) (string, bool) {
	// 查找32字节密钥数据
	for i := 0; i < len(memory)-32; i++ {
		keyData := memory[i : i+32]

		// 验证密钥
		if validator != nil {
			if validator.Validate(keyData) {
				return hex.EncodeToString(keyData), true
			} else if validator.ValidateImgKey(keyData) {
				return hex.EncodeToString(keyData[:16]), true
			}
		} else if s.isValidKeyPattern(keyData) {
			return hex.EncodeToString(keyData), true
		}
	}

	return "", false
}

func (s *WeixinDLLSearch) isValidKeyPattern(data []byte) bool {
	// 检查数据是否符合密钥特征
	allZero := true
	allSame := true
	firstByte := data[0]

	for _, b := range data {
		if b != 0 {
			allZero = false
		}
		if b != firstByte {
			allSame = false
		}
		if !allZero && !allSame {
			break
		}
	}

	return !allZero && !allSame
}

// AddStrategy 添加搜索策略
func (e *V4Extractor) AddStrategy(strategy SearchStrategy) {
	e.strategies = append(e.strategies, strategy)
}

// SetStrategies 设置搜索策略列表
func (e *V4Extractor) SetStrategies(strategies []SearchStrategy) {
	e.strategies = strategies
}
