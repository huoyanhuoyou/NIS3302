#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include "myfw.h"
//这一个是用户层代码
 
//------全局变量------
//创建一个全局变量，将要添加规则时的信息进行保留
Rule *pd_temp;
 
//------函数声明------
void printError(char* msg);//输出错误信息的函数
void printSuccess(char* msg);//输出成功信息的函数
void usage(char* program);//输出一些信息
unsigned int str2Ip(char* ipstr);//字符串类型的ip转换为整型
char* ip2Str(unsigned int ip, char buf[32]);//将整型的ip转为字符型的ip
unsigned short str2Port(char* portstr);//将端口转为整型
char* port2Str(unsigned short port, char buf[16]);//将整型端口构造为字符
char* protocol2Str(unsigned short protocol, char buf[16]);//将整型协议进行转为字符串
unsigned short str2Protocol(char* protstr);//将字符串类型的协议转为短整型的协议
void printRuleTable(RuleTable* rtb);//将规则集中的规则输出
int set(int cmd, void* val, int val_len, int sockfd);//将信息传到内核对规则进行修改
int get(int cmd, int sockfd);//将规则集进行输出或输出debug_level
int parseArgs(int argc, char* argv[], int* cmd, void* val, int* val_len);//获取用户端输入的信息并进行处理
 
//------主函数------
int main(int argc, char *argv[])
{
	int ret = -1;
	int cmd;
	char val[sizeof(Rule)];
	int val_len;
	int get_set = parseArgs(argc, argv, &cmd, val, &val_len);//将输入的参数进行处理
	if (get_set)//如果函数返回值不为零
	{
		int sockfd;
		//创建套接字，SOCK_RAW是RAW类型，提供原始网络协议访问
		//AF_INET设置地址族，IPPRPTP_RAW：原始IP数据包
		if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
			printError("socket()");//创建套接字失败输出错误信息
		else
		{
			if (get_set > 0)
				ret = set(cmd, val, val_len, sockfd);
				//将信息传到内核层，对规则集进行修改
			else ret = get(cmd, sockfd);
			close(sockfd);//关闭套接字
		}
	}
	else usage(argv[0]);//到这里说明是输入不对，对输入的格式进行提示
	return ret;//结束用户端程序
}
 
//------函数实现------
void printError(char* msg)//输出错误信息的函数
{
	printf("%s error %d: %s\n", msg, errno, strerror(errno));
}
 
void printSuccess(char* msg)//输出成功信息的函数
{
	printf("%s success\n", msg);
}
 
void usage(char* program)//输出一些输入格式信息
{
	printf("please check your input，the correct input format is:\n");
	printf("%s debug\n", program);
	printf("%s debug debug_level\n", program);
	printf("%s rule add sip sport dip dport protocol a|r\n", program);
	printf("%s rule del rule_number\n", program);
	printf("%s rule\n", program);
}
 
unsigned int str2Ip(char* ipstr)//字符串类型的ip转换为整型
{
	unsigned int ip;
	if (!strcmp(ipstr, "any"))ip = 0;//如果是any，表示任何任何端口或ip都可以，用0表示
	else inet_pton(AF_INET, ipstr, &ip);//将ip地址转换为用于网络传输的数值格式
	return ip;
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
 
unsigned short str2Port(char* portstr)//将端口转为整型
{
	unsigned short port;
	if (!strcmp(portstr, "any"))port = 0;
	else port = atoi(portstr);
	return port;
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
 
unsigned short str2Protocol(char* protstr)//将字符串类型的协议转为短整型的协议
{
	unsigned short protocol = 0;
	if (!strcmp(protstr, "any")) protocol = 0;//0表示任何端口
	else if (!strcmp(protstr, "ICMP"))protocol = MYFW_ICMP;
	else if (!strcmp(protstr, "TCP"))protocol = MYFW_TCP;
	else if (!strcmp(protstr, "UDP"))protocol = MYFW_UDP;
	return protocol;
}
 
void printRuleTable(RuleTable* rtb)//将规则集中的规则输出
{
	char sip[32], dip[32], sport[16], dport[16], protocol[16];
	Rule* r = &(rtb->rule);
	printf("Rules count: %d\n", rtb->count);
	for (int i = 0; i < rtb->count; i++){//遍历规则集
		ip2Str(r->sip, sip);//将源ip进行转换
		ip2Str(r->dip, dip);//将目的地址进行转换
		port2Str(r->sport, sport);//将源端口进行转换
		port2Str(r->dport, dport);//将目的端口进行转换
		protocol2Str(r->protocol, protocol);//将协议进行转换
		//进行输出
		printf("%d\t%s:%s -> %s:%s, %s is %s\n", i + 1, sip, sport, dip, dport, protocol, r->allow ? "allow" : "reject");
		r = r + 1;//移到下一个规则
	}
}
 
int set(int cmd, void* val, int val_len, int sockfd)//将信息传到内核对规则进行修改
{
	//val_len表示的是数据类型的长度，不是规则集的个数
	int ret = -1;
	//判断要添加的规则或要删除的规则是否在规则集中
	int new_val_len = 1024 * 1024;
	void* new_val = malloc(new_val_len);
	//从内核层获取规则表
	if (getsockopt(sockfd, IPPROTO_IP, CMD_RULE, new_val, &new_val_len))
		printError("getsockopt");//输出错误信息，说明从内核层获取信息失败
	else {
		RuleTable* rules = (RuleTable*)new_val;
		Rule* r = &(rules->rule);
		if (cmd == CMD_RULE_DEL) {//要进行删除操作
			RuleTable* rules2 = (RuleTable*)val;
			if (rules2->count > rules->count) {//说明规则集中不存在该规则
				printf("failed to delete：the rule to delete does not exist\n");
				return 0;//不存在不需要删除
			}
		}
		else if (cmd == CMD_RULE) {
			for (int i = 0; i < rules->count; i++) {//遍历规则集,判断是否已经存在要添加的规则。
				if (pd_temp->allow == r->allow && pd_temp->dip == r->dip &&
					pd_temp->dport == r->dport && pd_temp->protocol == r->protocol
					&& pd_temp->sip == r->sip && pd_temp->sport == r->sport) {
					printf("failed to add：rule to add already exists\n");
					return 0;//已存在不需要添加
				}
				r = r + 1;//移到下一个规则
			}
		}
		
	}
	//若无错误发生，setsockopt返回0，否则返回socket_error错误
	if (setsockopt(sockfd, IPPROTO_IP, cmd, val, val_len))
		printError("setsockopt()");//输出错误信息，说明消息传到内核失败或创建套接字失败
	else{
		printf("setsockopt() success\n");//前后的长度不相同说明添加或删除成功
		//获取当前的规则集并进行输出
		//从内核层获取规则表
		int new_val_len1 = 1024 * 1024;
		void* new_val1 = malloc(new_val_len1);
		if (getsockopt(sockfd, IPPROTO_IP, CMD_RULE, new_val1, &new_val_len1))
			printError("getsockopt");//输出错误信息，说明从内核层获取信息失败
		else {
			printf("Current rule set:\n");
			printRuleTable(new_val1);//将规则集进行输出
		}
		ret = 0;
	}
	return ret;
}
 
int get(int cmd, int sockfd)//将规则集进行输出或输出debug_level
{
	int ret = -1;
	int val_len = 1024 * 1024;
	void* val = malloc(val_len);
	if (getsockopt(sockfd, IPPROTO_IP, cmd, val, &val_len))printError("getsockopt");//输出错误信息
	else{
		switch (cmd){
		case CMD_DEBUG://如果输入的是debug，那么输出debug等级
			printf("debug level=%d\n", *(int*)val);
			break;
		case CMD_RULE://输入的是rule，则将规则集中的数据进行输出
			printRuleTable((RuleTable*)val);
			break;
		}
	}
	return ret;
}
 
int parseArgs(int argc, char* argv[], int* cmd, void* val, int* val_len)//获取用户端输入的信息并进行处理
{
	int ret = 0;//初始将ret设为0
	//argc是输入的参数个数
	//argv数组是存放输入的参数
	if (argc == 2){//说明不需要添加或者删除规则
		if (!strcmp(argv[1], "debug")){
			*cmd = CMD_DEBUG;
			ret = -1;
		}
		else if (!strcmp(argv[1], "rule")){
			*cmd = CMD_RULE;
			ret = -1;
		}
	}
	else if (argc > 2){
		if (!strcmp(argv[1], "debug") && argc == 3){
			*cmd = CMD_DEBUG;
			*(int*)val = atoi(argv[2]);
			*val_len = sizeof(int);
			ret = 1;
		}
		else if (!strcmp(argv[1], "rule")){//说明要对规则进行操作
			if (argc == 4){
				if (!strcmp(argv[2], "del")){//删除规则
					*cmd = CMD_RULE_DEL;
					*(int*)val = atoi(argv[3]);
					*val_len = sizeof(int);
					ret = 1;
				}
			}
			else if (argc == 9){
				if (!strcmp(argv[2], "add")){//添加规则
					*cmd = CMD_RULE;
					Rule* r = (Rule*)val;
					*val_len = sizeof(Rule);
					r->sip = str2Ip(argv[3]);//下面都是对输入的参数进行处理，将字符串转为数字或其他类型
					r->sport = str2Port(argv[4]);
					r->dip = str2Ip(argv[5]);
					r->dport = str2Port(argv[6]);
					r->protocol = str2Protocol(argv[7]);
					r->allow = strcmp(argv[8], "a") ? 0 : 1;//如果是a，说明是允许通信，赋值为1，否则赋值为0
					pd_temp = r;//将变量保存，用于后面添加规则时进行判断
					ret = 1;
				}
			}
		}
	}
	return ret;
}