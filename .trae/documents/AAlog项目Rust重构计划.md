# AAlog项目Rust重构计划

## 项目概述

AAlog（chatlog）是一个聊天记录工具，用于从本地微信数据库文件获取聊天数据，支持Windows/macOS系统，提供Terminal UI、命令行工具和HTTP API服务。

## 重构目标

1. 使用Rust语言完整移植现有功能
2. 修复所有警告信息
3. 保持原有功能和API不变
4. 优化代码结构和性能

## 重构步骤

### 1. 项目初始化

* 创建Cargo.toml文件，配置项目基本信息和依赖

* 建立基本目录结构，对应原有Go项目结构

### 2. 核心模块重构

#### 2.1 数据模型

* 重构internal/model目录下的数据结构

* 实现聊天记录、联系人、群聊等核心模型

* 处理Protobuf相关定义

#### 2.2 微信操作模块

* 重构internal/wechat目录下的功能

* 实现进程检测、密钥提取、数据解密等功能

* 处理跨平台差异（Windows/macOS）

#### 2.3 数据库模块

* 重构internal/wechatdb目录下的功能

* 实现数据库连接、查询、数据处理等功能

* 支持微信3.x/4.0版本数据库

#### 2.4 命令行工具

* 重构cmd/chatlog目录下的命令行功能

* 使用clap库实现命令行解析

* 实现各种子命令（decrypt、dumpmemory、key、server、version等）

#### 2.5 Terminal UI界面

* 重构internal/ui目录下的UI功能

* 使用tui-rs库实现终端UI

* 实现菜单、信息栏、页脚等组件

#### 2.6 HTTP API服务

* 重构internal/chatlog/http目录下的HTTP服务

* 使用axum库实现HTTP路由和处理

* 实现聊天记录、联系人、群聊等API接口

#### 2.7 MCP协议支持

* 重构internal/mcp目录下的MCP功能

* 实现MCP SSE协议，支持与AI助手集成

### 3. 公共工具模块

* 重构pkg目录下的公共工具函数

* 实现配置管理、文件操作、时间处理等功能

* 实现多媒体消息处理（图片、语音解密等）

### 4. 测试和调试

* 对每个模块进行单元测试

* 修复所有编译警告和错误

* 确保功能与原有项目一致

### 5. 优化和改进

* 优化代码结构，提高可读性和可维护性

* 优化性能，提高数据处理速度

* 添加更多错误处理和日志记录

* 实现TODO列表中的功能（聊天数据全文索引、统计\&Dashboard）

## 目录结构

```
- src/
  - cmd/
    - mod.rs
    - chatlog/
      - mod.rs
      - cmd_decrypt.rs
      - cmd_dumpmemory.rs
      - cmd_key.rs
      - cmd_server.rs
      - cmd_version.rs
      - root.rs
  - internal/
    - chatlog/
      - mod.rs
      - conf/
        - mod.rs
        - config.rs
        - service.rs
      - ctx/
        - mod.rs
        - context.rs
      - database/
        - mod.rs
        - service.rs
      - http/
        - mod.rs
        - route.rs
        - service.rs
      - mcp/
        - mod.rs
        - const.rs
        - service.rs
      - wechat/
        - mod.rs
        - service.rs
      - app.rs
      - manager.rs
    - errors/
      - mod.rs
      - errors.rs
      - http_errors.rs
      - middleware.rs
      - os_errors.rs
      - wechat_errors.rs
      - wechatdb_errors.rs
    - mcp/
      - mod.rs
      - error.rs
      - initialize.rs
      - jsonrpc.rs
      - mcp.rs
      - prompt.rs
      - resource.rs
      - session.rs
      - sse.rs
      - stdio.rs
      - tool.rs
    - model/
      - mod.rs
      - chatroom.rs
      - contact.rs
      - media.rs
      - message.rs
      - session.rs
      - wxproto/
        - mod.rs
    - ui/
      - mod.rs
      - footer/
        - mod.rs
        - footer.rs
      - form/
        - mod.rs
        - form.rs
      - help/
        - mod.rs
        - help.rs
      - infobar/
        - mod.rs
        - infobar.rs
      - menu/
        - mod.rs
        - menu.rs
        - submenu.rs
      - style/
        - mod.rs
        - style.rs
    - wechat/
      - mod.rs
      - decrypt/
        - mod.rs
        - common/
          - mod.rs
          - common.rs
        - darwin/
          - mod.rs
          - v3.rs
          - v4.rs
        - windows/
          - mod.rs
          - v3.rs
          - v4.rs
        - decryptor.rs
        - validator.rs
      - key/
        - mod.rs
        - darwin/
          - mod.rs
          - glance/
            - mod.rs
            - glance.rs
            - sip.rs
            - vmmap.rs
          - v3.rs
          - v4.rs
        - windows/
          - mod.rs
          - v3.rs
          - v3_others.rs
          - v3_windows.rs
          - v4.rs
          - v4_others.rs
          - v4_windows.rs
        - extractor.rs
      - model/
        - mod.rs
        - process.rs
      - process/
        - mod.rs
        - darwin/
          - mod.rs
          - detector.rs
        - windows/
          - mod.rs
          - detector.rs
          - detector_others.rs
          - detector_windows.rs
        - detector.rs
      - manager.rs
      - wechat.rs
    - wechatdb/
      - mod.rs
      - datasource/
        - mod.rs
        - darwinv3/
          - mod.rs
          - datasource.rs
        - dbm/
          - mod.rs
          - dbm.rs
          - group.rs
        - v4/
          - mod.rs
          - datasource.rs
        - windowsv3/
          - mod.rs
          - datasource.rs
        - datasource.rs
      - repository/
        - mod.rs
        - chatroom.rs
        - contact.rs
        - media.rs
        - message.rs
        - repository.rs
        - session.rs
      - wechatdb.rs
  - pkg/
    - mod.rs
    - appver/
      - mod.rs
      - version.rs
    - config/
      - mod.rs
      - config.rs
      - default.rs
    - filecopy/
      - mod.rs
      - filecopy.rs
    - filemonitor/
      - mod.rs
      - filegroup.rs
      - filemonitor.rs
    - util/
      - mod.rs
      - dat2img/
        - mod.rs
        - dat2img.rs
        - imgkey.rs
        - wxgf.rs
      - lz4/
        - mod.rs
        - lz4.rs
      - silk/
        - mod.rs
        - silk.rs
      - zstd/
        - mod.rs
        - zstd.rs
      - os.rs
      - strings.rs
      - time.rs
    - version/
      - mod.rs
      - version.rs
  - main.rs
- Cargo.toml
- Cargo.lock
- README.md
```

## 依赖库选择

* **命令行解析**：clap

* **终端UI**：tui-rs

* **HTTP服务**：axum

* **异步运行时**：tokio

* **日志**：tracing

* **配置管理**：config

* **数据库操作**：rusqlite

* **Protobuf**：prost

* **加密解密**：openssl

* **文件监控**：notify

## 重构时间线

1. **项目初始化**：1天
2. **核心数据模型**：2天
3. **微信操作模块**：3天
4. **数据库模块**：2天
5. **命令行工具**：1天
6. **Terminal UI界面**：2天
7. **HTTP API服务**：2天
8. **MCP协议支持**：1天
9. **公共工具模块**：1天
10. **测试和调试**：2天
11. **优化和改进**：2天

## 注意事项

1. 所有函数都需要添加中文注释，包含参数和返回值
2. 修复所有编译警告和错误
3. 保持原有功能和API不变
4. 注意跨平台兼容性
5. 确保性能和稳定性
6. 遵循Rust最佳实践

## 提交策略

1. 创建初始重构分支 `rust-refactor`
2. 完成基础框架后提交第一个版本
3. 逐步添加功能，每个功能模块完成后提交
4. 修复所有警告后提交最终重构版本
5. 切换到 `dev_rust` 分支进行功能优化
6. 每个优化功能完成后提交

## 功能优化计划

1. 聊天数据全文索引
2. 聊天数据统计 & Dashboard
3. 优化数据解密速度
4. 增强错误处理和日志记录
5. 改进UI界面，提高用户体验
6. 支持更多微信版本
7. 添加更多多媒体格式支持
8. 优化内存使用
9. 添加单元测试和集成测试
10. 改进文档和示例

