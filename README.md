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

## 基线状态

`detector/detector.py` 对每条失败登录和每个请求各产出一条告警，不做任何关联：
不看失败之后有没有成功登录，不看同账号是否跨主机，也不看请求路径是否敏感。

## 标注事件

| kind | 说明 |
|---|---|
| `web_scan` | 敏感路径扫描 |
| `webshell` | 上传后执行 webshell |
| `privilege_escalation` | 提权 |

日志里另有故意放入的**良性相似流量**（少量失败后成功、被拒绝的少量探测），任何命中都算误报。
