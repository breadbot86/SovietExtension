<p align="center">
  <img src="./3.1.png" width="900" alt="SovietExtension Banner" />
</p>

<h1 align="center">SovietExtension 苏维埃助手</h1>

<p align="center">
  For 开源共产主义，For 理想主义。<br/>
  免费的，抽象的，令人愉快的 Mac 微信插件。
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-macOS-lightgrey.svg" />
  <img src="https://img.shields.io/badge/Apple%20Silicon-M%20Chip-brightgreen.svg" />
  <img src="https://img.shields.io/badge/WeChat-4.0%2B-07C160.svg" />
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/fstudio/clangbuilder.svg" />
  </a>
  <a href="https://996.icu">
    <img src="https://img.shields.io/badge/link-996.icu-red.svg" />
  </a>
</p>

---

## Effect / 效果展示
> 自定义**殺馬特**效果速度、大小、强度，殺馬特or高级感全凭各位自己手艺，我更喜欢殺馬特而已。

> 🔞→嗳丄了祢℡ωǒ…吥徻↘後悔∵╭→很嗳﹎∩ 答应 ↘永逺┈⊕┈与∩ì.在∟┅ ↑起❤️
<p align="center">
  <img src="./colorful1.gif" width="1000" alt="SovietExtension Effect 1" />
</p>

<p align="center">
  <img src="./1.8.png" width="1000" alt="SovietExtension Effect 1" />
</p>

<p align="center">
  <img src="./1.9.png" width="1000" alt="SovietExtension Effect 2" />
</p>

<p align="center">
  <img src="./2.2.png" width="1000" alt="SovietExtension Effect 3" />
</p>

<p align="center">
  <img src="./4.1.png" width="1000" alt="SovietExtension Effect 2" />
</p>

<p align="center">
  <img src="https://star-history.dera.page/svg?repos=MustangYM/SovietExtension&type=Date" width="600" alt="SovietExtension Effect 3" />
</p>

---

## Features / 功能一览

### 常驻功能（菜单「苏维埃助手」）

阻止更新、消息防撤回（他人/本人）、撤回同步转发、群退群监控、多开、自动登录、迷离模式、侧边栏入口管理等，详见上效果图与各版本说明。

### 🔑 提取密钥

一键在微信进程内提取全部本地数据库（SQLCipher）密钥，按 wxid 存档：

* 进程内 crib-drag 扫描，**无需 sudo**，与微信版本无关（不依赖二进制偏移）；
* 候选密钥经数据库页 HMAC 密码学校验，只保存正确结果；
* 存档格式与 [wechat-cli-mac](https://github.com/onekb/wechat-cli-mac) 的 `all_keys.json` 兼容；
* 已提取过会自动跳过，重登/重建库后只补提新增。

### 🗄 数据库浏览器

用已提取的密钥解密并浏览全部本地数据库（有密钥存档时菜单才可点击）：

* **简易模式**：把库结构整理成人话——聊天消息按「会话名」分组（自动解析 MD5 表名、发送者映射昵称、时间格式化、消息类型中文化）、联系人、会话列表、小程序（含名称，来自 wacontact）；
* **专业模式**：账号 ▶ 数据库 ▶ 表 的原始树形浏览，适合查库调试；
* **内容直读**：WCDB zstd 压缩的消息内容自动解压显示（系统消息/图片消息的 XML 直接可读）；
* **媒体预览**：选中图片消息显示原图，视频消息直接播放（msg/video 明文 MP4），动图回退缩略图；
* 分页加载（500/页）、左右分栏、全部本地解密，数据不出本机。

> 密钥存档位于 `~/Library/Application Support/SovietExtension/Keys/`，解密副本缓存于系统临时目录（0700 权限，24h 自动清理）。请妥善保管密钥文件。

---

## Supported Version / 支持版本

> **睁大眼睛看：目前只支持下表列出的 Apple Silicon / M 芯片版本。**
> 本人没有 Intel 机器，无法开发和测试 Intel 版本，所以 Intel 版目前无效。
> 微信 4.x QT 化之后逆向起来比较麻烦，其他版本随缘适配。
> 代码已完全开源，可自行查看，爱你。

请注意：[微信官网](https://mac.weixin.qq.com/) 显示的大版本号可能一致，但实际小版本和 Build 号可能不同。
使用前请务必核对完整版本号和 Build 号。

| 微信版本      | Build 号 | Apple Silicon / M 芯片 | Intel | 下载地址                                                                        | 说明                       |
| --------- | ------: | :------------------: | :---: | --------------------------------------------------------------------------- | ------------------------ |
| 4.1.15.22 |  270102 |         ✅ 支持         | ❌ 不支持 | [Github 归档](https://github.com/zsbai/wechat-versions/releases/tag/4.1.15.22)           | 撤回拦截（含原消息类型/内容）、本人防撤回（保留重新编辑）、撤回同步转发、消息菜单 +1/访达定位/另存为、多开、防更新、侧边栏入口管理、退群监控均已适配；新增「提取密钥」与「数据库浏览器」（详见功能一览） |
| 4.1.11.23 |  269079 |         ✅ 支持         | ❌ 不支持 | [Github 归档](https://github.com/zsbai/wechat-versions/releases/tag/4.1.11.23)           | [1.1.2](https://github.com/MustangYM/SovietExtension/releases/tag/1.1.2) 已测试 |
| 4.1.10.53 |  268853 |         ✅ 支持         | ❌ 不支持 | [微信官网](https://weixin.qq.com/updates?platform=mac&version=4.1.10)           | 截止 2026-06-19，我在官网下载到的版本 |

> 不在表格中的版本暂不保证可用。
> 即使大版本看起来一样，只要 Build 号不同，也可能无法使用。

[wechat-versions历史版本下载](https://github.com/zsbai/wechat-versions/releases)
---

## Install / 安装

### 1. 先打开一次微信

如果是刚安装的微信，请先手动打开一次微信，然后再安装插件。

否则安装完成后，可能会提示：

```text
“xxx” 已损坏，无法打开。
```

### 2. 执行安装脚本

进入 `Rely` 文件夹，执行 `install.sh`：

```bash
cd SovietExtension/Rely
sh install.sh
```

或者直接执行完整路径：

```bash
sh /Users/mustangym/SovietExtension/SovietExtension/Rely/install.sh
```

安装后打开微信，如出现权限提示，请按引导完成授权。

安装过程示例：

```text
mustangym@macdeMacBook-Pro Rely % sh /Users/mustangym/SovietExtension/SovietExtension/Rely/install.sh

==============================
 Install SovietExtension
==============================

APP_PATH=/Applications/WeChat.app
PLUGIN_SRC_PATH=/Users/mustangym/SovietExtension/SovietExtension/Rely/Plugin/SovietExtension.framework
FRAMEWORK_DST_PATH=/Applications/WeChat.app/Contents/MacOS/SovietExtension.framework
INSERT_DYLIB_PATH=/Users/mustangym/SovietExtension/SovietExtension/Rely/insert_dylib
SUPPORTED_FILE=/Users/mustangym/SovietExtension/SovietExtension/Rely/supported_versions.txt
LOAD_DYLIB_PATH=@executable_path/SovietExtension.framework/SovietExtension

👉 [INFO] Detected WeChat version / 检测到微信版本:
    CFBundleShortVersionString: 4.1.9
    CFBundleVersion:            268602

✅ [OK] Version supported / 版本检查通过
    Supported Display Version: 4.1.9.58
    Matched Rule:              4.1.9.58|4.1.9|268602|Tested on Mac WeChat 4.1.9.58

...省略一万句...

👉 [INFO] Verify code signature / 检查签名...
⚠️  [WARN] Code signature verification failed, but app may still run for debugging / 签名验证未完全通过，但调试运行不一定受影响

==============================
✅ SovietExtension installed successfully
✅ SovietExtension 安装完成
==============================

Run WeChat and watch log / 启动微信并查看日志：
  rm -f /tmp/YMWeChatAntiRevokePatch.log
  open -a WeChat
  tail -f /tmp/YMWeChatAntiRevokePatch.log

Uninstall / 卸载：
  /Users/mustangym/SovietExtension/SovietExtension/Rely/uninstall.sh
```

---

## Troubleshooting / 常见问题

### 1. 提示 `Operation not permitted`

如果安装时报错：

```text
cp: xxxxx: Operation not permitted
```

请到：

```text
系统设置 → 隐私与安全性
```

给你当前运行脚本的“终端工具”开启以下权限：

| 权限                          | 说明         |
| --------------------------- | ---------- |
| 完整磁盘访问权限 / Full Disk Access | 允许脚本修改应用目录 |
| 文件与文件夹 / Files and Folders  | 允许访问相关文件   |

常见终端工具包括：

* Terminal / 终端
* iTerm2
* VSCode
* Cursor
* Warp

你用哪个工具执行脚本，就给哪个工具开权限。

### 2. 如果反复弹窗提示[”微信“想访问其他App的数据]
```text
在系统设置中打开微信”完全磁盘访问“，如果微信已经在里面，则删除后重新添加。
```

---

### 3. 提示版本不支持

请确认你的微信版本和 Build 号是否在支持表格中。

查看方式：

```bash
defaults read /Applications/WeChat.app/Contents/Info.plist CFBundleShortVersionString
defaults read /Applications/WeChat.app/Contents/Info.plist CFBundleVersion
```

只有表格中明确列出的版本才保证可用。

---

### 4. 安装后微信打不开

可以先执行卸载脚本恢复：

```bash
sh /Users/mustangym/SovietExtension/SovietExtension/Rely/uninstall.sh
```

如果仍然打不开，可以删除微信后重新安装官方版本。

---

## Uninstall / 卸载

进入 `Rely` 文件夹，执行：

```bash
sh uninstall.sh
```

或者直接执行完整路径：

```bash
sh /Users/mustangym/SovietExtension/SovietExtension/Rely/uninstall.sh
```

---

## Notes / 说明

* 本项目仅用于学习、研究与个人折腾。
* 代码完全开源，可自行查看实现。
* 不接受除 Bug 以外的任何 Issue。
* 不接受任何形式的捐赠与收费。
* 其他版本适配随缘，别催，催就是你对。

---

## Thanks / 致谢

感谢湖畔大学全体同学。

**瑞思拜。**

MustangYM.

---

## License / 开源协议

<a href="LICENSE">
  <img src="https://img.shields.io/github/license/fstudio/clangbuilder.svg" />
</a>

<a href="https://996.icu">
  <img src="https://img.shields.io/badge/link-996.icu-red.svg" />
</a>
