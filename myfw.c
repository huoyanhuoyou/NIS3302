#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/skbuff.h>//包含sk_buff结构
#include<linux/tcp.h>
#include<linux/netdevice.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/udp.h>

#include"header.h"

//unimportant function declaration
void debugInfo(char* msg);

//定义detfilter的5个钩子点：
static struct nf_hook_ops nfhoLocalIn;
static struct nf_hook_ops nfhoLocalOut;
static struct nf_hook_ops nfhoPreRouting;
static struct nf_hook_ops nfhoForward;
static struct nf_hook_ops nfhoPostRouting;
//创建套接字选项，与用户层通信
static struct nf_sockopt_ops nfhoSockopt;

//global variable
static int debug_level = 0;
static int nfcount = 0;

//Rules
static Rule* g_rules;	//group of rules
static int g_rules_current_count = 0;	// quantity of rules that exist
static int g_rules_total_count = 0;	//quantity of rules that have been created

//state variable
static int del_succeed = 0;
static int add_succeed = 0;
static int alt_succeed = 0;

//Key function declaration
void addRule(Rule* rule);
void delRule(int rule_id);
int checkExistance(Rule* rule);
int matchRule(void* skb);
void altRule(Rule_with_tag* tag_rule);

/*
**requires inspection**
*/
unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)//sk_buff就是传入的数据包，*skb
{
	unsigned rc = NF_ACCEPT;//默认继续传递，保持和原来输出的一致
 
	if (matchRule(skb))//查规则集，如果返回值<=0，那么不允许进行通信
		rc = NF_DROP;//丢弃包，不再继续传递
 
 
	return rc;//返回是是否允许通信，是否丢包
}
 
unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	debugInfo("hookLocalOut");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	debugInfo("hookPreRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookPostRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	debugInfo("hookPostRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookForward(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	debugInfo("hookForwarding");
	return NF_ACCEPT;//接收该数据
}
 
int hookSockoptSet(struct sock* sock,
	int cmd,
	void __user* user,
	unsigned int len)//用于接收用户端数据的函数
{
	int ret;

	switch(cmd){
		case CMD_SET_DEBUG_STATE:
			ret = copy_from_user(&debug_level, user, sizeof(debug_level));
			break;

		case CMD_ADD_RULE:
			Rule* val=vmalloc(sizeof(Rule));
			ret = copy_from_user(val, user, sizeof(Rule));
			addRule(val);
			break;
		
		case CMD_DEL_RULE:
			int rule_id;
			ret = copy_from_user(&rule_id, user, sizeof(int));
			delRule(rule_id);
			break;

		case CMD_ALT_RULE:
			Rule_with_tag* tag_rule = vmalloc(sizeof(Rule_with_tag));
			ret = copy_from_user(tag_rule, user, sizeof(Rule_with_tag));
			printk("Debug: point 1.\n");
			altRule(tag_rule);
			break;
			

		default:
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

	switch (cmd){
		case CMD_GET_DEBUG_STATE:
			ret = copy_to_user(user, &debug_level, sizeof(debug_level));
			break;

		case CMD_GET_RULES:
			ret = copy_to_user(user, &g_rules_current_count, sizeof(g_rules_current_count));
			ret = copy_to_user(user + sizeof(g_rules_current_count), g_rules, sizeof(Rule) * g_rules_current_count);
			break;

		case CMD_DEL_RULE:
			ret = copy_to_user(user, &del_succeed, sizeof(del_succeed));
			break;

		case CMD_ADD_RULE:
			ret = copy_to_user(user, &add_succeed, sizeof(add_succeed));
			break;

		case CMD_ALT_RULE:
			ret = copy_to_user(user, &alt_succeed, sizeof(alt_succeed));
			break;
		
		default:
			break;
    }

    if (ret != 0){
		ret = -EINVAL;
		debugInfo("copy_to_user error");
	}

    return ret;
}
 
// key funtions definations
void addRule(Rule* rule){
	// check existance
	if(!checkExistance(rule)){
		int n_g_rules_current_count = g_rules_current_count + 1;
		int n_g_rules_total_count = g_rules_total_count + 1;
		rule->id = n_g_rules_total_count;
		Rule* g_r = (Rule*)vmalloc(n_g_rules_current_count * sizeof(Rule));

		if(g_rules_current_count > 0){
			memcpy(g_r, g_rules, g_rules_current_count * sizeof(Rule));
			vfree(g_rules);
		}
		memcpy(g_r + g_rules_current_count, rule, sizeof(Rule));

		g_rules = g_r;
		g_rules_current_count = n_g_rules_current_count;
		g_rules_total_count = n_g_rules_total_count;

		add_succeed = 1;
	}else{
		add_succeed = 0;
	}
	
	
}

void delRule(int rule_id){
	Rule* ptr = g_rules;	// find the head
	int found=-1;
	for(int i=0;i<g_rules_current_count;++i){
		if((ptr+i)->id == rule_id){	//find the target rule
			found = i;
			break;
		}
	}

	if(found != -1){// if found
		for(int i = found+1; i<g_rules_current_count;++i){
			memcpy(g_rules + i - 1, g_rules + i, sizeof(Rule));
		}
		g_rules_current_count--;
		
		del_succeed = 1;
	}else{
		del_succeed = 0;
	}
	
	
}

void altRule(Rule_with_tag* tag_rule){
	Rule* ptr = g_rules;
	Rule* target = NULL;
	int found = 0;
	for(int i=0; i<g_rules_current_count;++i){
		if((ptr+i)->id == tag_rule->id){
			found = 1;
			target = ptr + i;
			break;
		}
	}
	if(found){
		if(tag_rule->mark_bit.protocol == 1) target->protocol = tag_rule->rule.protocol;
		if(tag_rule->mark_bit.sip == 1) target->sip = tag_rule->rule.sip;
		if(tag_rule->mark_bit.dip == 1) target->dip = tag_rule->rule.dip;
		if(tag_rule->mark_bit.sport == 1) target->sport = tag_rule->rule.sport;
		if(tag_rule->mark_bit.dport == 1) target->dport = tag_rule->rule.dport;

		alt_succeed = 1;
	}else{
		alt_succeed = 0;
	}
}


// end key function definations


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

void debugInfo(char* msg)//记录操作次数，将每次的操作信息输出到日志
{
	if (debug_level){//如果等级符合要求，才进行+1和输出到日志
		nfcount++;
		printk("%s, nfcount: %d\n", msg, nfcount);
	}
}

int checkExistance(Rule* rule){
	Rule* ptr = NULL;
	for(int i = 0; i < g_rules_current_count; ++i){
		ptr = (Rule*)g_rules + i;
		if(ptr->sip == rule->sip && ptr->sport == rule->sport 
			&& ptr->dip == rule->dip && ptr->dport == rule->dport
				&& ptr->protocol == rule->protocol){
					return 1;
				}
	}
	return 0;
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
	for (i = 0; i < g_rules_current_count; i++){//遍历规则集
		r = g_rules + i;//用r来遍历
		if ((!r->sip || r->sip == iph->saddr) &&
			(!r->dip || r->dip == iph->daddr) &&
			(!r->protocol || r->protocol == iph->protocol)){
			switch (iph->protocol){//对协议类型进行判断进行判断
			case MYFW_TCP:
				tcph = (struct tcphdr*)(skb_transport_header(skb));
				sport = tcph->source;
				dport = tcph->dest;
				break;
			case MYFW_UDP:
				udph = (struct udphdr*)(skb_transport_header(skb));
				sport = udph->source;
				dport = udph->dest;
				break;
			}
			if ((!r->sport || !sport || r->sport == sport) &&
				(!r->dport || !dport || r->dport == dport)){
				return MATCH;
			}
		}
	}
	return NMATCH;
}