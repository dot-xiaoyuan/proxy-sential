# 隔离校园流量实验

本工具只在本机 Docker 的内部网络或进程 loopback 上发流量。192.168.0.190 只用于另行认证联调，不作为流量压测目标。

## 构建

在项目根目录执行（Docker 为 ARM64 时；AMD64 将 GOARCH 改为 amd64）：

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o scripts/testbed/campus/campus-load ./cmd/campus-load
docker build -t sentinel-campus-lab:local scripts/testbed/campus
```

镜像使用 Alpine 3.21 的 tcpdump、Suricata、Python、OpenSSL、iproute2、iptables。构建需要软件仓库访问；运行时两个 Docker 网络均为 `--internal`。镜像没有启动 Redis 等其他服务。不挂载 Docker socket，不使用 host network 或 privileged。路由容器仅增加 NET_ADMIN/NET_RAW；容器退出后自动清理本次创建的容器及网络。

## 协议压力

```sh
go run ./cmd/campus-load --requests 10000 --concurrency 16 --rate 1000
go run ./cmd/campus-load --requests 100000 --concurrency 64 --rate 10000
go run ./cmd/campus-load --requests 1000000 --concurrency 128 --rate 10000
```

请求按 DNS、HTTP、TLS 均分，仅访问程序自己创建的 loopback 服务，无自定义目标参数。TLS 校验实验临时证书。请求数最多一百万、并发最多 256、目标速率最多每秒一万；中断停止提交新请求。记录实际速率、协议成功数、失败数、响应字节、延迟直方图的 p95 上界、抽样 Go 堆内存峰值。小响应和连接复用用于基础负载测试，不代表视频带宽、真实终端数或生产检测吞吐；Go 堆内存不是整机/进程 RSS。

## 实际 NAT 抓包

```sh
scripts/testbed/campus/run-nat.sh heterogeneous
scripts/testbed/campus/run-nat.sh single
scripts/testbed/campus/run-nat.sh multi_browser
scripts/testbed/campus/run-nat.sh homogeneous
python3 scripts/testbed/campus/analyze-nat.py <上一步输出目录>
```

固定隔离地址：服务端 172.29.250.10；路由出口 172.29.250.2；内部客户端 172.29.251.11/12，SNAT 后共享出口。Docker 若发现地址池冲突会失败，不删除或修改现有网络。

每组共 6,000 次实际 DNS/HTTP/TLS 请求，16 并发/负载进程。`single` 两个负载进程在同一容器、使用同一协议配置；`multi_browser` 在同一容器使用两组配置；`homogeneous` 两个容器使用相同配置；`heterogeneous` 两个容器使用不同配置和初始 TTL。Android/Windows 是编程设定的 UA、TLS 和 TTL 配置，不能宣称运行了真正的 Android/Windows 系统。

输出 PCAP、抓包丢包统计、Suricata EVE、解析器版本、客户端结果及场景标签。分析脚本检查出口 TTL、UA、JA3 的实际差异及丢包。抓包验收通过只证明网络拓扑和解析特征符合该实验设计，不等于账号归责或策略执行通过。实验临时服务证书公钥保存在结果目录；私钥留在服务容器 `/tmp` 并随容器删除。

## 标准事件消费者回放

```sh
go test ./internal/evidence -run '^TestCampusSharedReplay$' -count=1 -v
SENTINEL_CAMPUS_STRESS=1 go test ./internal/evidence -run '^TestCampusSharedReplay$' -count=1 -v
```

合成标准事件覆盖正常终端、多浏览器、UA 模拟、漫游、随机 MAC、共享 CDN、异构共享、同类共享、身份失效及重复事件。百万条模式分一千批执行，每批一千条。测试明确保留“同类共享未命中”结果，不把未知终端虚构为已确认设备。此项不包含真实抓包、数据库、任务调度和控制器动作；与 NAT 抓包结果分别验收。

## 尚需联调

真实抓包事件与权威身份的受控来源、园区和接入域登记；共享证据策略消费；真实流量持续写库与实时/历史并发；长连接/大响应/丢包故障场景；190 认证测试账号的动作及恢复。不得把上述分项测试拼成未经运行的端到端通过结论。

## 同时实采 TTL

构建 Linux 版 Sentinel 后，通过 `SENTINEL_CAPTURE_BINARY` 指定本地二进制路径运行 `run-nat.sh`。脚本将二进制只读挂载到隔离路由容器，在发流量前生成有效采集范围，运行 AF_PACKET TTL 采集器，并用同一实验范围转换 Suricata EVE。范围绑定的是本次实验实例，随采集进程重启必须更新。输出 `device-signals.jsonl`、`scoped-normalized.jsonl` 和 `capture-scope.json`。

使用 `SENTINEL_SHARED_CAPTURE_DIR=<结果目录的绝对路径> go test -race ./internal/evidence -run '^TestSharedLiveCaptureReplay$' -count=1 -v` 验证实采事件。测试读取实验生成的 `scenario.json`，不允许未知场景或缺失标签。分别验证无身份时未知，以及加入显式实验身份后的结果：异构共享为存在依据、单设备为未命中、多浏览器配置为证据不足、同类设备共享为未命中（已知漏检）。不声称使用了真实认证清单。
