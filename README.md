# detectlog

基于 Python 标准库的行式日志攻击检测器：按规则从日志中挑出可疑事件，
在滑动时间窗口内按维度聚合，达到阈值后产生告警并归并，最终输出 JSON 报告。
不依赖任何第三方包。

## 用法

```
python -m detectlog.cli --log <日志文件> --rules <规则文件> --out <报告路径>
```

demo：

```
python -m detectlog.cli --log demo/access.log --rules demo/rules.yaml --out out/report.json
```

运行结束后 stdout 打印一行摘要：`read=<读入行数> matched=<命中次数> alerts=<告警条数>`。

## 日志格式

解析器按行读取，自动识别两类常见格式：

- **key=value 行**：字段名不固定，按常见别名映射到规范字段
  （如 `src`/`client_ip`/`remote_addr` → `src_ip`，`url`/`uri` → `path`，
  `proc`/`cmd` → `command`，`dst`/`target` → `dst`）。
  值可以用双引号或单引号包裹以包含空格。未识别的键原样保留，规则也可直接引用。
- **Apache/Nginx common 格式**：按位置推断来源 IP、时间、方法、路径、状态码。

时间戳支持 ISO 8601（`2026-11-14T08:00:00Z`、带时区偏移、空格分隔）、
epoch 秒/毫秒、Apache 格式（`14/Nov/2026:08:00:00 +0000`）。
无法解析出时间戳的行会被跳过。事件先按时间戳排序再进入检测流程。

## 规则文件格式

规则文件是一个 YAML 子集（引擎自带解析器，支持缩进嵌套的字典/列表、
带引号或裸标量、`[a, b]` 行内列表、`#` 注释）：

```yaml
rules:
  - name: brute_force_login   # 规则名（必填，唯一）
    dimension: src_ip         # 聚合维度：任一规范字段或原始键名（必填）
    window: 300               # 滑动窗口秒数（必填）
    threshold: 10             # 窗口内命中达到该次数才确认（必填）
    merge_window: 60          # 归并窗口秒数（可选，默认 60）
    where:                    # 匹配条件列表（可选，缺省匹配所有行）
      - field: path           # 字段名；raw 表示整行原文
        pattern: /login       # 正则（re.search）
      - field: status
        pattern: "^(401|403)$"
```

条件操作符四选一：

- `pattern` / `not_pattern`：正则匹配 / 不匹配
- `in` / `not_in`：在 / 不在给定列表中；列表项可以是字符串、IP 或 CIDR 网段
  （如 `10.0.0.0/8`），用于“已登记目标地址”这类白名单

所有条件同时成立该行才算命中规则。条件引用的字段在事件中不存在时，该条件不成立。

## 窗口与归并语义

- 命中按 `(规则, 维度值)` 分桶，桶内维护长度为 `window` 秒的滑动窗口，
  窗口区间是左开右闭的 `(t - window, t]`：恰好早 `window` 秒的事件已滑出窗口。
- 窗口内命中数首次达到 `threshold` 时，该桶被**确认**，开出一条告警，
  覆盖窗口内的全部命中（`count` = 窗口内命中数）。
- 桶被确认后，其后的每条命中都会计入告警：
  距当前告警最后一次命中不超过 `merge_window` 秒的，归并进当前告警
  （`count` 累加、`last_seen` 顺延）；超过 `merge_window` 的，
  当前告警封口，以这条命中新开一条告警（`count` 从 1 记起）。
- 未达到阈值的桶不产生任何告警，其中的命中被丢弃。

因此窗口边界是精确的：例如阈值 10、窗口 300 秒时，第 10 次失败发生在第 0 秒、
第 11 次发生在第 301 秒，会得到两条告警（10 次与 1 次），而不是一条 11 次。

## 告警字段

报告 JSON 的 `alerts` 列表中，每条告警含七个字段：

| 字段 | 含义 |
| --- | --- |
| `rule` | 触发的规则名 |
| `dimension` | 聚合维度名（如 `src_ip`、`dst`） |
| `key` | 维度取值（如 `203.0.113.7`） |
| `count` | 归并进该告警的命中总次数 |
| `first_seen` | 首次命中时间（ISO 8601 UTC） |
| `last_seen` | 最后一次命中时间（ISO 8601 UTC） |
| `sample` | 一条代表性原始日志（取自日志中的真实行） |

报告另含 `summary`：`lines_read`（读入行数）、`lines_parsed`（成功解析行数）、
`matched`（规则命中次数）、`alerts`（告警条数）。

## 测试

```
python -m unittest test_detectlog -v        # 仓库根目录
python -m unittest discover -s tests -v     # 等价写法
```

