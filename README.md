# 压缩包上传与解压执行

业务允许上传 zip，压包里的内容会被自动解压到站点目录。

```
logs/auth.log   856 行（合成，含 3 起真实事件）
labels.json     3 个标注事件
detector/detector.py  基线检测器
tests/          骨架测试
```

## Run

```bash
python -m pytest tests -q
python detector/detector.py logs/auth.log findings.json
```

## 检测器

`detector/detector.py` 做事件关联，输出 `findings.json`（findings + needs_review）：

- `archive_webshell`：上传端点/压缩包请求 → 同 IP 在 1 小时内访问解压目录下的可执行文件（.php/.jsp/.exe 等），告警带 upload → extract → access 时间序列；
- `web_scan`：同一 IP 探测 ≥4 个不同敏感路径（少量被拒探测属背景噪声，不报）；
- `privilege_escalation`：普通账号 sudo 起 root shell 后 10 分钟内出现 root SSH 登录。

链路不完整的（只有上传没有访问、只有可执行文件访问没有上传记录、sudo 后无 root 登录）
进 `needs_review` 并注明缺哪一环，不算告警。

## 标注事件

| kind | 说明 |
|---|---|
| `web_scan` | 敏感路径扫描 |
| `webshell` | 上传后执行 webshell |
| `privilege_escalation` | 提权 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
