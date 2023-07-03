# 使用说明

## 安装内核模块并编译命令行操作界面

运行以下命令生成可执行文件和内核模块：
```
sudo bash ./install.sh
```
移除内核模块：
```
sudo bash ./uninstall.sh
```

## 命令行工具

### 增加规则

```
sudo ./cmdtool rule add [args]
```

`[args]`可选：

`-p`：ICMP、UDP、TCP；

`-x sip -y sport -m dip -n dport`

基于时间段的控制
`-d -w -s -e`：`-d`后接日期（1-31）；`-w`接星期，周日至周六分别以0-6表示；`-s -e`分别为开始时间，格式均为`hh:mm`。默认值：`00:00-24:00`。

### 展示所有规则

```
sudo ./cmdtool rule show
```

### 删除规则

```
sudo ./cmdtool rule del [rule_id]
```

欲删除多于一个规则，可以列举要删除的规则id：
```
sudo ./cmdtool rule del 1 3 7
```
上述命令删除id为1，3，7的命令。

### 修改规则

```
sudo ./cmdtool rule alt [rule_id] [args]
```

### 临时屏蔽规则

```
sudo ./cmdtool rule set [rule_id] [0/1]
```
其中，0为屏蔽规则，1为生效规则。

### 修改调试等级

```
sudo ./cmdtool debug set [0/1]
```

```
sudo ./cmdtool debug show
```
