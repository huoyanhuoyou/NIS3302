#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>//包含sk_buff结构
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
 
#include "myfw.h"
//内核层的代码
 
//使用静态变量更适合与模块化编程，使用static进行定义的结构或变量只能在本文件中使用
//定义detfilter的5个钩子点：
static struct nf_hook_ops nfhoLocalIn;
static struct nf_hook_ops nfhoLocalOut;
static struct nf_hook_ops nfhoPreRouting;
static struct nf_hook_ops nfhoForward;
static struct nf_hook_ops nfhoPostRouting;
//创建套接字选项，与用户层通信
static struct nf_sockopt_ops nfhoSockopt;
 
static int debug_level = 0;
static int nfcount = 0;
 
static Rule* g_rules;//规则集,用指针形式来记录可以更省空间
static int g_rules_count = 0;//用来记录规则的个数
 
//------函数声明------
void addRule(Rule* rule);//增加规则的函数
void delRule(int rule_num);//删除规则，输入的参数表示要删除的规则的编号
int matchRule(void* skb);//进行规则比较的函数，判断是否能进行通信
void debugInfo(char* msg);//记录操作次数，将每次的操作信息输出到日志
//sk_buff就是传入的数据包，*skb
unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
unsigned int hookPostRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
unsigned int hookForward(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
//用于接收用户端数据的函数
int hookSockoptSet(struct sock* sock, int cmd, void __user* user, unsigned int len);
//用与将数据传到用户层的函数
int hookSockoptGet(struct sock* sock, int cmd, void __user* user, int* len);
int init_module();//内核模块初始化,初始化五个钩子（进行钩子的注册）
void cleanup_module();//将钩子注销
 
//------函数实现------
void addRule(Rule* rule)//增加规则的函数
{
	//这一个函数是先将要添加的规则放入新的规则集中，再把原来的规则集放到新的规则集中
	//所以每次添加规则时，添加的规则都会放到第一位
	int r_c = g_rules_count + 1;//将规则个数+1
	Rule* g_r = (Rule*)vmalloc(r_c * sizeof(Rule));//开辟相应大小的空间
	memcpy(g_r, rule, sizeof(Rule));//将要增加的规则放到新开辟的规则集中
 
	if (g_rules_count > 0){//如果原规则集中有规则，则先将原来的规则集赋值给新规则集
		memcpy(g_r + 1, g_rules, g_rules_count * sizeof(Rule));
		vfree(g_rules);//回收之前的rule，释放空间
	}
 
	g_rules = g_r;//将新的规则集赋值给全局规则集
	g_rules_count = r_c;//更新规则集中规则的数量
}
 
void delRule(int rule_num)//删除规则，输入的参数表示要删除的规则的编号
{
	int i;
	if (rule_num > 0 && rule_num <= g_rules_count){//如果输入的规则编号有效，则进行删除
		for (i = rule_num; i < g_rules_count; i++){
			//把要删除的规则的位置之后的规则都往前移一个位置，将要删除的规则覆盖掉
			memcpy(g_rules + i - 1, g_rules + i, sizeof(Rule));
		}
		g_rules_count--;//最后一个空间闲着，不用管
	}
}
 
int matchRule(void* skb)//进行规则比较的函数，判断是否能进行通信
{
	//增加了端口控制的规则匹配
	int sport = 0;
	int dport = 0;
	struct iphdr* iph = ip_hdr(skb);
	struct tcphdr* tcph;
	struct udphdr* udph;
	int act = 1, i;
	Rule* r;
	for (i = 0; i < g_rules_count; i++){//遍历规则集
		r = g_rules + i;//用r来遍历
		if ((!r->sip || r->sip == iph->saddr) &&
			(!r->dip || r->dip == iph->daddr) &&
			(!r->protocol || r->protocol == iph->protocol)){
			switch (iph->protocol){//对协议类型进行判断进行判断
			case MYFW_TCP:
				tcph = (struct tcphdr*)skb_transport_header(skb);
				sport = tcph->source;
				dport = tcph->dest;
				break;
			case MYFW_UDP:
				udph = (struct udphdr*)skb_transport_header(skb);
				sport = udph->source;
				dport = udph->dest;
				break;
			}
			if ((!r->sport || !sport || r->sport == sport) &&
				(!r->dport || !dport || r->dport == dport)){
				act = r->allow;
			}
		}
	}
	return act;
}
 
void debugInfo(char* msg)//记录操作次数，将每次的操作信息输出到日志
{
	if (debug_level){//如果等级符合要求，才进行+1和输出到日志
		nfcount++;
		printk("%s, nfcount: %d\n", msg, nfcount);
	}
}
 
unsigned int hookLocalIn(void* priv,
	struct sk_buff* skb,//sk_buff就是传入的数据包，*skb
	const struct nf_hook_state* state)
{
	unsigned rc = NF_ACCEPT;//默认继续传递，保持和原来输出的一致
 
	if (matchRule(skb) <= 0)//查规则集，如果返回值<=0，那么不允许进行通信
		rc = NF_DROP;//丢弃包，不再继续传递
 
	debugInfo("hookLocalIn");
 
	return rc;//返回是是否允许通信，是否丢包
}
 
unsigned int hookLocalOut(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	debugInfo("hookLocalOut");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookPreRouting(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	debugInfo("hookPreRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookPostRouting(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	debugInfo("hookPostRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookForward(void* priv,
	struct sk_buff* skb,
	const struct nf_hook_state* state)
{
	debugInfo("hookForwarding");
	return NF_ACCEPT;//接收该数据
}
 
int hookSockoptSet(struct sock* sock,
	int cmd,
	void __user* user,
	unsigned int len)//用于接收用户端数据的函数
{
	int ret = 0;
	Rule r;
	int r_num;
 
	debugInfo("hookSockoptSet");
 
	switch (cmd){
	case CMD_DEBUG:
		//copy_from_user函数的作用：用于将用户空间的数据拷贝到内核空间
		ret = copy_from_user(&debug_level, user, sizeof(debug_level));
		printk("set debug level to %d", debug_level);//设置debug等级
		break;
	case CMD_RULE:
		ret = copy_from_user(&r, user, sizeof(Rule));//如果是添加规则
		addRule(&r);
		printk("add rule");//输出到日志
		break;
	case CMD_RULE_DEL:
		ret = copy_from_user(&r_num, user, sizeof(r_num));//删除规则
		delRule(r_num);
		printk("del rule");//输出到日志
		break;
	}
	if (ret != 0)//说明赋值失败，进行输出
	{
		printk("copy_from_user error");
		ret = -EINVAL;
	}
 
	return ret;
}
 
int hookSockoptGet(struct sock* sock,
	int cmd,
	void __user* user,
	int* len)//用与将数据传到用户层的函数
{
	int ret;
 
	debugInfo("hookSockoptGet");
 
	switch (cmd){
	case CMD_DEBUG:
		ret = copy_to_user(user, &debug_level, sizeof(debug_level));
		break;
	case CMD_RULE:
		//copy_to_user函数的作用：将内核空间的数据拷贝到用户空间
		//拷贝成功返回0
		ret = copy_to_user(user, &g_rules_count, sizeof(g_rules_count));
		ret = copy_to_user(user + sizeof(g_rules_count), g_rules, sizeof(Rule) * g_rules_count);
		break;
	}
 
	if (ret != 0){
		ret = -EINVAL;
		debugInfo("copy_to_user error");
	}
 
	return ret;
}
 
int init_module()//内核模块初始化,初始化五个钩子（进行钩子的注册）
{
	nfhoLocalIn.hook = hookLocalIn;//设置一些参数
	nfhoLocalIn.hooknum = NF_INET_LOCAL_IN;//注册回调函数
	nfhoLocalIn.pf = PF_INET;
	nfhoLocalIn.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalIn);//注册hook
 
	nfhoLocalOut.hook = hookLocalOut;
	nfhoLocalOut.hooknum = NF_INET_LOCAL_OUT;
	nfhoLocalOut.pf = PF_INET;
	nfhoLocalOut.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalOut);
 
	nfhoPreRouting.hook = hookPreRouting;
	nfhoPreRouting.hooknum = NF_INET_PRE_ROUTING;
	nfhoPreRouting.pf = PF_INET;
	nfhoPreRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPreRouting);
 
	nfhoForward.hook = hookForward;
	nfhoForward.hooknum = NF_INET_FORWARD;
	nfhoForward.pf = PF_INET;
	nfhoForward.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoForward);
 
	nfhoPostRouting.hook = hookPostRouting;
	nfhoPostRouting.hooknum = NF_INET_POST_ROUTING;
	nfhoPostRouting.pf = PF_INET;
	nfhoPostRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPostRouting);
 
	nfhoSockopt.pf = PF_INET;//PF_INET表示协议族
	nfhoSockopt.set_optmin = CMD_MIN;
	nfhoSockopt.set_optmax = CMD_MAX;
	nfhoSockopt.set = hookSockoptSet;
	nfhoSockopt.get_optmin = CMD_MIN;
	nfhoSockopt.get_optmax = CMD_MAX;
	nfhoSockopt.get = hookSockoptGet;
	nf_register_sockopt(&nfhoSockopt);//注册扩展套接字选项
 
	printk("myfirewall started\n");//将信息输出到日志中
 
	return 0;
}
 
void cleanup_module()//将钩子注销
{
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);//将5个hook注销
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForward);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);
 
	nf_unregister_sockopt(&nfhoSockopt);
 
	printk("myfirewall stopped\n");//输出相应的信息
}
 
MODULE_LICENSE("GPL");//模块的许可证声明，防止收到内核被污染的警告