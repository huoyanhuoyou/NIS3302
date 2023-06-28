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

`-x sid -y sport -m dip -n dport`

### 展示所有规则

```
sudo ./cmdtool rule show
```

### 删除规则

```
sudo ./cmdtool rule del [rule_id]
```

### 修改规则

```
sudo ./cmdtool rule alt [rule_id] [args]
```

### 修改调试等级

```
sudo ./cmdtool debug set [0/1]
```

```
sudo ./cmdtool debug show
```
