package windows

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/aspnmy/chatlog/internal/wechat/decrypt"
)

func TestV4Extractor_SearchKey(t *testing.T) {
	// 创建测试上下文
	ctx := context.Background()

	// 测试用例1：正常情况，包含密钥模式，无validator
	// 创建V4提取器，不设置validator
	extractor := NewV4Extractor()

	// 创建包含密钥模式的内存数据
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// 创建足够大的模拟内存数据
	memory := make([]byte, 0x10200)

	// 在内存中插入密钥模式和密钥
	// 1. 插入密钥数据（放在0x10000之后，符合指针检查条件）
	keyData := []byte("0123456789abcdef0123456789abcdef")
	keyOffset := 0x10100
	copy(memory[keyOffset:keyOffset+0x20], keyData)

	// 2. 插入密钥模式和指向密钥的指针
	ptrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptrBytes, uint64(keyOffset))
	copy(memory[0x200:0x208], ptrBytes)
	copy(memory[0x208:0x220], keyPattern)

	// 调用SearchKey方法
	key, found := extractor.SearchKey(ctx, memory)
	if !found {
		t.Error("测试用例1失败：没有找到密钥")
	}
	if key == "" {
		t.Error("测试用例1失败：返回的密钥为空")
	}
	t.Logf("测试用例1成功：找到密钥 %s", key)

	// 测试用例2：没有找到密钥的情况
	// 创建不包含密钥模式的内存数据
	memory2 := make([]byte, 0x1000)
	copy(memory2, "test data without key pattern")

	key2, found2 := extractor.SearchKey(ctx, memory2)
	if found2 {
		t.Error("测试用例2失败：不应该找到密钥")
	}
	if key2 != "" {
		t.Error("测试用例2失败：返回的密钥不应该不为空")
	}
	t.Logf("测试用例2成功：正确返回没有找到密钥")

	// 测试用例3：validator为空的情况（应该返回找到的密钥，用于测试）
	extractor2 := NewV4Extractor()
	key3, found3 := extractor2.SearchKey(ctx, memory)
	if !found3 {
		t.Error("测试用例3失败：validator为空时应该找到密钥")
	}
	if key3 == "" {
		t.Error("测试用例3失败：validator为空时返回的密钥不应该为空")
	}
	t.Logf("测试用例3成功：validator为空时正确返回找到的密钥 %s", key3)

	// 测试用例4：指针超出内存范围的情况
	// 创建指针超出范围的内存数据
	memory4 := make([]byte, 0x100)
	copy(memory4[0:8], ptrBytes) // 指针指向0x100，但内存只有0x100字节
	copy(memory4[8:24], keyPattern)

	key4, found4 := extractor.SearchKey(ctx, memory4)
	if found4 {
		t.Error("测试用例4失败：指针超出范围时不应该找到密钥")
	}
	if key4 != "" {
		t.Error("测试用例4失败：指针超出范围时返回的密钥不应该不为空")
	}
	t.Logf("测试用例4成功：指针超出范围时正确处理")

	// 测试用例5：密钥长度不足的情况
	memory5 := make([]byte, 0x200)
	// 插入指向内存末尾的指针
	shortPtr := make([]byte, 8)
	binary.LittleEndian.PutUint64(shortPtr, 0x1F0) // 指向内存末尾，密钥长度不足
	copy(memory5[0:8], shortPtr)
	copy(memory5[8:24], keyPattern)

	key5, found5 := extractor.SearchKey(ctx, memory5)
	if found5 {
		t.Error("测试用例5失败：密钥长度不足时不应该找到密钥")
	}
	if key5 != "" {
		t.Error("测试用例5失败：密钥长度不足时返回的密钥不应该不为空")
	}
	t.Logf("测试用例5成功：密钥长度不足时正确处理")
}

func BenchmarkV4Extractor_SearchKey(b *testing.B) {
	// 创建测试上下文
	ctx := context.Background()

	// 创建V4提取器
	extractor := NewV4Extractor()

	// 创建模拟验证器
	validator := &decrypt.Validator{}
	extractor.SetValidate(validator)

	// 创建测试数据
	keyPattern := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// 创建模拟内存数据
	memory := make([]byte, 0x10000) // 64KB内存

	// 在内存中插入多个密钥模式
	for i := 0; i < 10; i++ {
		// 插入密钥数据
		keyData := make([]byte, 0x20)
		for j := range keyData {
			keyData[j] = byte(i + j)
		}
		copy(memory[i*0x1000:i*0x1000+0x20], keyData)

		// 插入密钥模式和指针
		ptrBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(ptrBytes, uint64(i*0x1000))
		copy(memory[i*0x1000+0x100:i*0x1000+0x108], ptrBytes)
		copy(memory[i*0x1000+0x108:i*0x1000+0x124], keyPattern)
	}

	// 运行基准测试
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.SearchKey(ctx, memory)
	}
}
