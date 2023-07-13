#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/skbuff.h>//包含sk_buff结构
#include<linux/tcp.h>
#include<linux/netdevice.h>
#include<linux/netfilter.h>
#include<linux/netfilter_ipv4.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include <linux/icmp.h>
#include<linux/time.h>
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
int i = 0;

char c_sip[32];
char c_dip[32];
char c_sport[16];
char c_dport[16];
char c_protocol[16];

//Rules
static Rule* g_rules;	//group of rules
static int g_rules_current_count = 0;	// quantity of rules that exist
static int g_rules_total_count = 0;	//quantity of rules that have been created

//state variable
static int del_succeed = 0;
static int add_succeed = 0;
static int alt_succeed = 0;
static int change_rule_stat = 0;

//Key function declaration
void addRule(Rule* rule);
void delRule(int rule_id);
int checkExistance(Rule* rule);
int matchRule(void* skb);
void altRule(Rule_with_tag* tag_rule);
void changeRuleStat(int rule_id, int blocked);
Rule* searchRuleById(int id);
void get_skb_outgoing_interface_mac(struct sk_buff *skb, unsigned char *mac_addr);
int isEqual(Control_Time *ct1, Control_Time *ct2);
int matchDay(struct tm *tm1, Control_Time* ct);
int stringsAreEqual(const char* str1, const char* str2) ;
/*
**requires inspection**
*/

//util function
unsigned int str2Ip(char* ipstr);//字符串类型的ip转换为整型
char* ip2Str(unsigned int ip, char buf[32]);//将整型的ip转为字符型的ip
unsigned short str2Port(char* portstr);//将端口转为整型
char* port2Str(unsigned short port, char buf[16]);//将整型端口构造为字符
char* protocol2Str(unsigned short protocol, char buf[16]);//将整型协议进行转为字符串
unsigned short str2Protocol(char* protstr);//将字符串类型的协议转为短整型的协议
char* skb_mac2print_mac(const unsigned char* mac);//

void get_skb_outgoing_interface_mac(struct sk_buff *skb, unsigned char *mac_addr) {
	struct net_device *dev = skb_dst(skb)->dev;
    // 检查出口接口是否有效
    if (dev) {
        // 获取出口接口的 MAC 地址
        memcpy(mac_addr, dev->dev_addr, ETH_ALEN);
    }
}


unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)//sk_buff就是传入的数据包，*skb
{
	unsigned rc = NF_ACCEPT;//默认继续传递，保持和原来输出的一致
 
	//printk("Existing rules:%d",g_rules_current_count);
	if (matchRule(skb))//查规则集，如果返回值<=0，那么不允许进行通信
		rc = NF_DROP;//丢弃包，不再继续传递
 
 
	return rc;//返回是是否允许通信，是否丢包
}
 
unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	unsigned rc = NF_ACCEPT;//默认继续传递，保持和原来输出的一致
 
	//printk("Existing rules:%d",g_rules_current_count);
	if (matchRule(skb))//查规则集，如果返回值<=0，那么不允许进行通信
		rc = NF_DROP;//丢弃包，不再继续传递
 
 
	return rc;//返回是是否允许通信，是否丢包
}
 
unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	//debugInfo("hookPreRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookPostRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	//debugInfo("hookPostRouting");
	return NF_ACCEPT;//接收该数据
}
 
unsigned int hookForward(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	//debugInfo("hookForwarding");
	return NF_ACCEPT;//接收该数据
}
 
int hookSockoptSet(struct sock* sock,
	int cmd,
	void __user* user,
	unsigned int len)//用于接收用户端数据的函数
{
	int ret;

	
		if(cmd == CMD_SET_DEBUG_STATE)
		{
			ret = copy_from_user(&debug_level, user, sizeof(debug_level));
			
			//record
			printk("[Myfw]Changed debug level to %d.\n",debug_level);
			
		}
		if(cmd == CMD_ADD_RULE)
		{
			Rule* val=vmalloc(sizeof(Rule));
			ret = copy_from_user(val, user, sizeof(Rule));
			addRule(val);
			
		}
		if(cmd == CMD_DEL_RULE)
		{
			int rule_id;
			ret = copy_from_user(&rule_id, user, sizeof(int));
			delRule(rule_id);
			
		}
		if(cmd == CMD_ALT_RULE)
		{
			Rule_with_tag* tag_rule = vmalloc(sizeof(Rule_with_tag));
			ret = copy_from_user(tag_rule, user, sizeof(Rule_with_tag));
			printk("Debug: point 1.\n");
			altRule(tag_rule);
			
		}
		if(cmd == CMD_RULE_STATE)
		{
			RuleStat* rule_stat=vmalloc(sizeof(RuleStat));
			ret = copy_from_user(rule_stat, user, sizeof(RuleStat));
			changeRuleStat(rule_stat->rule_id, rule_stat->blocked);
			
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

		case CMD_RULE_STATE: 
			ret = copy_to_user(user, &change_rule_stat, sizeof(change_rule_stat));
			break;
		
		default:
			break;
    }

    if (ret != 0){
		ret = -EINVAL;
		//debugInfo("copy_to_user error");
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

		if(debug_level){
			printk("A new rule was added, id: %d.\n", rule->id);
		}


		add_succeed = 1;
	}else{
		add_succeed = 0;
	}
	
	
}

void delRule(int rule_id){
	Rule* ptr = g_rules;	// find the head
	int found=-1;

	

	for(i=0;i<g_rules_current_count;++i){
		if((ptr+i)->id == rule_id){	//find the target rule
			found = i;
			break;
		}
	}

	if(found != -1){// if found
	int target_id = (g_rules + found)->id;
		for(i = found+1; i<g_rules_current_count;++i){
			memcpy(g_rules + i - 1, g_rules + i, sizeof(Rule));
		}
		g_rules_current_count--;
		
		if(debug_level){
			printk("Rule %d was deleted!\n", target_id);
		}

		del_succeed = 1;
	}else{
		del_succeed = 0;
	}
	
	
}

void altRule(Rule_with_tag* tag_rule){
	Rule* target = searchRuleById(tag_rule->id);
	if (target == NULL){// not found
		alt_succeed = 0;
		return;
	}

	Rule* temp = vmalloc(sizeof(Rule));
	//copy target to temp
	memcpy(temp, target, sizeof(Rule));

	if(tag_rule->mark_bit.protocol == 1) temp->protocol = tag_rule->rule.protocol;
	if(tag_rule->mark_bit.sip == 1) temp->sip = tag_rule->rule.sip;
	if(tag_rule->mark_bit.dip == 1) temp->dip = tag_rule->rule.dip;
	if(tag_rule->mark_bit.sport == 1) temp->sport = tag_rule->rule.sport;
	if(tag_rule->mark_bit.dport == 1) temp->dport = tag_rule->rule.dport;
	if(tag_rule->mark_bit.indev_mac ==1) strcmp(temp->indev_mac, tag_rule->rule.indev_mac);
	if(tag_rule->mark_bit.outdev_mac ==1) strcmp(temp->outdev_mac, tag_rule->rule.outdev_mac);
	if(tag_rule->mark_bit.ICMP_type ==1) temp->ICMP_type = tag_rule->rule.ICMP_type;
	if(tag_rule->mark_bit.ct_date == 1)	temp->controlled_time.date = tag_rule->rule.controlled_time.date;
	if(tag_rule->mark_bit.ct_wday == 1) temp->controlled_time.wday = tag_rule->rule.controlled_time.wday;
	if(tag_rule->mark_bit.ct_stime == 1){
		temp->controlled_time.s_hour = tag_rule->rule.controlled_time.s_hour;
		temp->controlled_time.s_min = tag_rule->rule.controlled_time.s_min;
	}
	if(tag_rule->mark_bit.ct_etime == 1){
		temp->controlled_time.e_hour = tag_rule->rule.controlled_time.e_hour;
		temp->controlled_time.e_min = tag_rule->rule.controlled_time.e_min;
	}

	if(checkExistance(temp)){
		alt_succeed = 2;// marks already exists
	}else{
		memcpy(target, temp, sizeof(Rule));

		if(debug_level){
			printk("Rule %d was changed!\n", target->id);
		}


		alt_succeed = 1;
	}

	vfree(temp);
}

void changeRuleStat(int rule_id, int blocked){
	Rule* target = searchRuleById(rule_id);
	if(target != NULL){
		target->block = blocked;

		change_rule_stat = 1;
	}
	else{
		change_rule_stat = 0;
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
		//nfcount++;
		//printk("%s, nfcount: %d\n", msg, nfcount);

		printk("[Myfw]%s.\n", msg);
		
	}
}

int checkExistance(Rule* rule){
	Rule* ptr = NULL;
	for(i = 0; i < g_rules_current_count; ++i){
		ptr = (Rule*)g_rules + i;
		if(ptr->sip == rule->sip && ptr->sport == rule->sport 
			&& ptr->dip == rule->dip && ptr->dport == rule->dport
				&& ptr->protocol == rule->protocol
					&& ptr->ICMP_type == rule->ICMP_type
						&& !strcmp(ptr->indev_mac, rule->indev_mac)
							&& !strcmp(ptr->outdev_mac, rule->outdev_mac)
								&& isEqual(&(ptr->controlled_time), &(rule->controlled_time))){
					return 1;
				}
	}
	return 0;
}

Rule* searchRuleById(int id){
	Rule* ptr = g_rules;
	Rule* target = NULL;
	for(i=0; i<g_rules_current_count;++i){
		if((ptr+i)->id == id){
			target = ptr + i;
			break;
		}
	}
	return target;
}

int matchRule(void* skb)//进行规则比较的函数，判断是否能进行通信
{
	//增加了端口控制的规则匹配
	time64_t n = ktime_get_real_seconds() + 8*3600;//get current time
	struct tm tm;
	time64_to_tm(n, 0, &tm);
	
	int sport = 0;
	int dport = 0;
	struct iphdr* iph = ip_hdr(skb);
	//获取数据包中的eth_hdr结构体
	struct ethhdr *eth_hdr = (struct ethhdr *)skb_mac_header(skb);
	//得到接入接口mac地址
	unsigned char indev_mac[ETH_ALEN];
	if(skb_mac_header_was_set(skb))
	{  //将数据包skb的ethhdr结构体中的目的mac地址赋给接入接口mac地址；
		memcpy(indev_mac, eth_hdr->h_dest, ETH_ALEN);
	}
	//获取数据包中的接出mac地址；
	unsigned char outdev_mac[ETH_ALEN];

    // 获取 skb 数据包的出口接口 MAC 地址
    struct net_device *dev = skb_dst(skb)->dev;
    // 检查出口接口是否有效
    if (dev) {
        // 获取出口接口的 MAC 地址
        memcpy(outdev_mac, dev->dev_addr, ETH_ALEN);
	}
	//将skb中的mac地址转换为输出格式
	char i_mac[18];
	char o_mac[18];
	sprintf(i_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
        indev_mac[0], indev_mac[1], indev_mac[2], indev_mac[3], indev_mac[4], indev_mac[5]);
	sprintf(o_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
        outdev_mac[0], outdev_mac[1], outdev_mac[2], outdev_mac[3], outdev_mac[4], outdev_mac[5]);

	char void_mac[18] = "00:00:00:00:00:00";//定义虚拟网络接口

	__u8 icmp_type;
	
    // skb包含ICMP协议
	struct icmphdr *icmp = icmp_hdr(skb);
	icmp_type = icmp->type;
	int i_type = (int)icmp_type;
	//将icmp报文子类型由u8型转为int型
	struct tcphdr* tcph;
	struct udphdr* udph;
	
	Rule* r;
	for (i = 0; i < g_rules_current_count; i++){//遍历规则集
		r = g_rules + i;//用r来遍历
		if(r->block) continue; //if blocked, then ignore

		//check time
		
		if(!(matchDay(&tm, &(r->controlled_time)))) continue;	
		//check time end


		//check time end

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
			if ((!(int)r->sport || !sport || (int)r->sport == sport) &&
				(!(int)r->dport || !dport || (int)r->dport == dport)){
				if (r->ICMP_type ==-1 || r->ICMP_type == icmp_type)
						{
							if(!strcmp(r->indev_mac,"any") ||!strcmp(r->indev_mac , i_mac))//对网络接口设备接入口地址进行判别
							{
								if(!strcmp(r->outdev_mac,"any") || !strcmp(r->outdev_mac , o_mac))
									{
										//debug info
										ip2Str(iph->saddr, c_sip);
										ip2Str(iph->daddr, c_dip);
										port2Str(sport, c_sport);
										port2Str(dport, c_dport);
										protocol2Str(iph->protocol, c_protocol);

										if(debug_level){
											if(iph->protocol == 1)
											printk("[Myfw] Reject packet:(%s)%s:%s -> %s:%s\t indev_mac:%s outdev_mac:%s ICMP_type:%d according to Rule %d",c_protocol, c_sip, c_sport, c_dip, c_dport, i_mac, o_mac, i_type, r->id);
											else
											printk("[Myfw] Reject packet:(%s)%s:%s -> %s:%s\t indev_mac:%s outdev_mac:%s ICMP_type:Null according to Rule %d",c_protocol, c_sip, c_sport, c_dip, c_dport, i_mac, o_mac, r->id);
										}

										return MATCH;
									}
							}		
						}
			}
		}
	}
	return NMATCH;
}

int matchDay(struct tm *tm1, Control_Time* ct){
	int wdaymatch = 0;
	int timematch = 0;
	int datematch = 0;

	if(ct->wday == -1 || tm1->tm_wday == ct->wday) wdaymatch = 1;
	if(ct->date == -1 || tm1->tm_mday == ct->date) datematch = 1;

	int s_time = 60*(ct->s_hour) + ct->s_min;
	int e_time = 60*(ct->e_hour) + ct->e_min;
	int now = 60*(tm1->tm_hour) + tm1->tm_min;

	if(s_time < now && now < e_time){
		timematch = 1;
	}
	// printk("%d, %d", ct->wday, tm1->tm_wday);
	// printk("%d,%d,%d\n",wdaymatch,timematch,datematch);

	return (wdaymatch && timematch && datematch);
}

int isEqual(Control_Time *ct1, Control_Time *ct2){
	if(ct1->date != ct2->date) return 0;
	if(ct1->wday != ct2->wday) return 0;
	if(ct1->s_hour != ct2->s_hour) return 0;
	if(ct1->s_min != ct2->s_min) return 0;
	if(ct1->e_hour != ct2->e_hour) return 0;
	if(ct1->e_min != ct2->e_min) return 0;
	return 1;
}

char* ip2Str(unsigned int ip, char buf[32])//将整型的ip转为字符型的ip
{
	if (ip){
		unsigned char* c = (unsigned char*)&ip;
		sprintf(buf, "%d.%d.%d.%d", *c, *(c + 1), *(c + 2), *(c + 3));
	}
	else sprintf(buf, "any");
	return buf;
}

char* port2Str(unsigned short port, char buf[16])//将整型端口构造为字符
{
	if (port)sprintf(buf, "%d", port);
	else sprintf(buf, "any");
	return buf;
}

char* protocol2Str(unsigned short protocol, char buf[16])//将整型协议进行转为字符串
{
	switch (protocol){
	case 0:
		strcpy(buf, "any");
		break;
	case MYFW_ICMP:
		strcpy(buf, "ICMP");
		break;
	case MYFW_TCP:
		strcpy(buf, "TCP");
		break;
	case MYFW_UDP:
		strcpy(buf, "UDP");
		break;
	default:
		strcpy(buf, "Unknown");
	}
	return buf;
}

int stringsAreEqual(const char* str1, const char* str2) {
    int i = 0;
    while (str1[i] == str2[i]) {
        if (str1[i] == '\0') {
            return 0; // 字符串相等
        }
        i++;
    }
    return 1; // 字符串不相等
}

char* skb_mac2print_mac(const unsigned char* mac) {
    char mac_str[ETH_ALEN * 3];  // 存储转换后的 MAC 地址字符串
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	
	return mac_str;
}