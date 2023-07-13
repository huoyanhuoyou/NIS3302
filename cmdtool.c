#include"header.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<arpa/inet.h>
#include<unistd.h>
#include<pthread.h>
#include<signal.h>
#include<errno.h>
#include<getopt.h>

void paramsError();//use when params error
void showUsage();


//key function
void showRules(int sockfd);
void addRule(int sockfd, int argc, char* argv[]);
void delRule(int sockfd, int argc, char* argv[]);
void altRule(int sockfd, int argc, char* argv[]);
void setRuleStat(int sockfd, int rule_id, int active);

void showDebugState(int sockfd);
void setDebugState(int sockfd, int state);
//end key function

//utils function
unsigned int str2Ip(char* ipstr);//字符串类型的ip转换为整型
char* ip2Str(unsigned int ip, char buf[32]);//将整型的ip转为字符型的ip
unsigned short str2Port(char* portstr);//将端口转为整型
char* port2Str(unsigned short port, char buf[16]);//将整型端口构造为字符
char* protocol2Str(unsigned short protocol, char buf[16]);//将整型协议进行转为字符串
unsigned short str2Protocol(char* protstr);//将字符串类型的协议转为短整型的协议
void str2mac(char* r_mac, const char* getmac);
unsigned int str2ICMP_type(char* type);
char* mac2str(char *dev_mac);
char* ICMP_type(int type);
//end utils function

/*
Command tool for Tiny Firewall. Should support:
    ./cmdtool rule show
    ./cmdtool rule add
    ./cmdtool rule del
    ./cmdtool rule alt
    ./cmdtool rule block 
    ./cmdtool debug show
    ./cmdtool debug set [value]
*/

int main(int argc, char* argv[]){
    // check if help
    if(argc < 1){
        paramsError("Need command!");
        exit(-1);
    }

    if(!strncmp(argv[1],"help",4)){
        showUsage();
        exit(-1);
    }
    

    //create sockfd
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    //check sockfd
    if(sockfd == -1){
        printf("socket() failed! Check your sudo mod.\n");
        exit(-1);
    }

    int op = 0; //defination of operator
    if(!strncmp(argv[1], "rule", 4)) op = 1;
    if(!strncmp(argv[1], "debug", 5)) op = 2;

    if(op == 0){
        paramsError("Only support command: rule and debug!");
        exit(-1);
    }

    if(argc < 3){
        paramsError("Too few arguments!");
        exit(-1);
    }

    switch (op)
    {
    case 1:
        if(!strncmp(argv[2], "show", 4)){
            showRules(sockfd);
            break;
        }
        if(!strncmp(argv[2], "add", 3)){
            addRule(sockfd, argc, argv);
            break;
        };
        if(!strncmp(argv[2], "del", 3)){
            delRule(sockfd, argc, argv);
            break;
        };
        if(!strncmp(argv[2], "alt", 3)){
            altRule(sockfd, argc, argv);
            break;
        }
        if(!strncmp(argv[2], "set", 3)){                    //改变debug_level
            setRuleStat(sockfd, atoi(argv[3]), atoi(argv[4]));
            break;
        }
        paramsError("Command not found in rule!");
        break;
    
    case 2:
        if(!strncmp(argv[2], "show", 4)){
            showDebugState(sockfd);
            break;
        }
        if(!strncmp(argv[2], "set", 3)){                    //改变debug_level
            if(argc < 4) paramsError("Too few arguments!");
            setDebugState(sockfd, atoi(argv[3]));
            break;
        }
        break;
    default:
        paramsError("Command not found in debug!");
        break;
    }
    close(sockfd);
    return 0;
}
//function main() over.

void paramsError(char *info){
    printf("Invalid command! %s Use \'help\' to show usage!\n", info);
    exit(-1);
}

void showRules(int sockfd){
    // get rules list from kernel
    int val_len = 1024 * 1024;
    void* val = malloc(val_len);
    getsockopt(sockfd, IPPROTO_IP, CMD_GET_RULES, val, &val_len);
    //
    RuleTable* tbl = (RuleTable*)val;
    Rule* r = &(tbl->rule);
    printf("Existing number of rules: %d.\n", tbl->count);
    
    char sip[32], dip[32], sport[32], dport[32], protocol[16],indev_mac[17],outdev_mac[17];
    
    int id, blocked;
    for(int i = 0; i<tbl->count; ++i){
        id = r->id;
        blocked = r->block;         
        ip2Str(r->sip, sip);
        ip2Str(r->dip, dip);
        port2Str(r->sport, sport);
        port2Str(r->dport, dport);
        protocol2Str(r->protocol, protocol);
        //转换输出格式
        
        if(r->ICMP_type == -1) 
        {
            char* ICMP_type = "any or none";
            printf("Rule %d: \t%s:%s -> %s:%s, protocol:%s, indev_mac:%s, outdev_mac:%s, ICMP_type:%s is \t%s (%d, %d, %02d:%02d - %02d:%02d)\n", id, sip, sport, dip, dport, protocol,r->indev_mac,r->outdev_mac, ICMP_type, (blocked) ? "blocked": "active",  r->controlled_time.wday, r->controlled_time.date, r->controlled_time.s_hour, r->controlled_time.s_min, r->controlled_time.e_hour, r->controlled_time.e_min);
        }
        else 
        {
            printf("Rule %d: \t%s:%s -> %s:%s, protocol:%s, indev_mac:%s, outdev_mac:%s, ICMP_type:%d is \t%s\n", id, sip, sport, dip, dport, protocol,r->indev_mac,r->outdev_mac, r->ICMP_type, (blocked) ? "blocked": "active");
        }
        r = r + 1;
    }

}

void addRule(int sockfd, int argc, char* argv[]){
    Rule* new_rule = malloc(sizeof(Rule));
    //new_rule->indev_mac = (char*)malloc(20 * sizeof(char));
    //new_rule->outdev_mac = (char*)malloc(20 * sizeof(char));
    new_rule->id = 0;
    new_rule->block = 0;
    new_rule->controlled_time.date = -1;
    new_rule->controlled_time.wday = -1;
    new_rule->controlled_time.s_hour = 0;
    new_rule->controlled_time.s_min = 0;
    new_rule->controlled_time.e_hour = 24;
    new_rule->controlled_time.e_min = 0;

    char *sip;
    char *dip; 
    char *sport; 
    char *dport; 
    char *protocol;
    char* any = "any";
    char *indev_mac;
    char *outdev_mac;
    char *ICMP_type;
    sip = any;
    dip = any;
    sport = any;
    dport = any;
    protocol = any;
    indev_mac = any;
    outdev_mac = any;
    ICMP_type = any;

    // read params
    char optret;
    char *hourStr, *minStr;
    while((optret = getopt(argc, argv, "p:x:y:m:n:b:i:o:t:d:w:s:e:")) != -1){
        switch(optret){
            case 'p':
                protocol = optarg;
                break;
            
            case 'x':
                sip = optarg;
                break;

            case 'y':
                sport = optarg;
                break;

            case 'm':
                dip = optarg;
                break;

            case 'n':
                dport = optarg;
                break;

            case 'b':
                new_rule->block = atoi(optarg);
                break;

            case 'i':
                indev_mac = optarg;
                break;
            
            case 'o':
                outdev_mac = optarg;
                break;

            case 't':
                ICMP_type = optarg;
                break;

            case 'd':
                new_rule->controlled_time.date = atoi(optarg);
                break;

            case 'w':
                new_rule->controlled_time.wday = atoi(optarg);
                break;

            case 's':
                hourStr = strtok(optarg, ":");
                minStr = strtok(NULL, ":");

                new_rule->controlled_time.s_hour = atoi(hourStr);
                new_rule->controlled_time.s_min = atoi(minStr);
                break;

            case 'e':
                hourStr = strtok(optarg, ":");
                minStr = strtok(NULL, ":");

                new_rule->controlled_time.e_hour = atoi(hourStr);
                new_rule->controlled_time.e_min = atoi(minStr);
                break;
            
        }
    }

    new_rule->dip = str2Ip(dip);
    new_rule->sip = str2Ip(sip);
    new_rule->dport = str2Port(dport);
    new_rule->sport = str2Port(sport);
    new_rule->protocol = str2Protocol(protocol);
    str2mac(new_rule->indev_mac, indev_mac);
    str2mac(new_rule->outdev_mac, outdev_mac);
    
    new_rule->ICMP_type = str2ICMP_type(ICMP_type);
    void* val=(void*)new_rule;

    setsockopt(sockfd, IPPROTO_IP, CMD_ADD_RULE, val, sizeof(Rule));
    free(new_rule);

    int res;
    int var_len = sizeof(int);
    getsockopt(sockfd, IPPROTO_IP, CMD_ADD_RULE, &res, &var_len);
    if(res){
        printf("Add rule succeed!\n");
    }else{
        printf("Rule already exists!\n");
    }
}

void delRule(int sockfd, int argc, char* argv[]){
    for(int i = 3; i < argc; ++i){
        int rule_id = atoi(argv[i]);
        setsockopt(sockfd, IPPROTO_IP, CMD_DEL_RULE, &rule_id, sizeof(int));
        int res;
        int val_len = sizeof(int);
        getsockopt(sockfd, IPPROTO_IP, CMD_DEL_RULE, &res, &val_len);
        if(res){
            printf("Delete rule %d successfully!\n", rule_id);
        }
        else{
            printf("Rule %d not found!\n", rule_id);
        }
    }

}

void altRule(int sockfd, int argc, char* argv[]){
    Rule* alt_rule = malloc(sizeof(Rule));
    //alt_rule->indev_mac = (char*)malloc(20 * sizeof(char));
    //alt_rule->outdev_mac = (char*)malloc(20 * sizeof(char));
    Rule_Mark_Bit* alt_rule_mark_bit = malloc(sizeof(Rule_Mark_Bit));

    int target_id = atoi(argv[3]);

    // init mark bit
    alt_rule_mark_bit->sip = 0;
    alt_rule_mark_bit->dip = 0;
    alt_rule_mark_bit->sport = 0;
    alt_rule_mark_bit->dport = 0;
    alt_rule_mark_bit->protocol = 0;
    alt_rule_mark_bit->indev_mac = 0;
    alt_rule_mark_bit->outdev_mac = 0;
    alt_rule_mark_bit->ICMP_type = 0;
    alt_rule_mark_bit->ct_date = 0;
    alt_rule_mark_bit->ct_wday = 0;
    alt_rule_mark_bit->ct_stime = 0;
    alt_rule_mark_bit->ct_etime = 0;
    // get params and process
    char *hourStr, *minStr;
    char optret;
    while((optret = getopt(argc, argv, "p:x:y:m:n:i:o:t:d:w:s:e:")) != -1){
        switch (optret){
            case 'p':
                alt_rule->protocol = str2Protocol(optarg);
                alt_rule_mark_bit->protocol = 1;
                break;

            case 'x':
                alt_rule->sip = str2Ip(optarg);
                alt_rule_mark_bit->sip = 1;
                break;

            case 'y':
                alt_rule->sport = str2Port(optarg);
                alt_rule_mark_bit->sport = 1;
                break;

            case 'm':
                alt_rule->dip = str2Ip(optarg);
                alt_rule_mark_bit->dip = 1;
                break;

            case 'n':
                alt_rule->dport = str2Port(optarg);
                alt_rule_mark_bit->dport = 1;
                break;
            
            case 'i':
                str2mac(alt_rule->indev_mac, optarg);
                //alt_rule->indev_mac = *optarg;
                alt_rule_mark_bit->indev_mac = 1;
                break;

            case 'o':
                str2mac(alt_rule->outdev_mac, optarg);
                //alt_rule->outdev_mac = *optarg;
                alt_rule_mark_bit->outdev_mac = 1;
                break;

            case 't':
                alt_rule->ICMP_type = str2ICMP_type(optarg);
                alt_rule_mark_bit->ICMP_type = 1;
                break;

            case 'd':
                alt_rule->controlled_time.date = atoi(optarg);
                alt_rule_mark_bit->ct_date = 1;
                break;

            case 'w':
                alt_rule->controlled_time.wday = atoi(optarg);
                alt_rule_mark_bit->ct_wday = 1;
                break;

            case 's':
                hourStr = strtok(optarg, ":");
                minStr = strtok(NULL, ":");

                alt_rule->controlled_time.s_hour = atoi(hourStr);
                alt_rule->controlled_time.s_min = atoi(minStr);
                alt_rule_mark_bit->ct_stime = 1;
                break;

            case 'e':
                hourStr = strtok(optarg, ":");
                minStr = strtok(NULL, ":");

                alt_rule->controlled_time.e_hour = atoi(hourStr);
                alt_rule->controlled_time.e_min = atoi(minStr);
                alt_rule_mark_bit->ct_etime = 1;
                break;
        }
    }
    Rule_with_tag* tag_rule = malloc(sizeof(Rule_with_tag));
    tag_rule->id = target_id;
    tag_rule->rule = *alt_rule;
    tag_rule->mark_bit = *alt_rule_mark_bit;

    setsockopt(sockfd, IPPROTO_IP, CMD_ALT_RULE, tag_rule, sizeof(Rule_with_tag));

    int res;                    //返回结果
    int res_len = sizeof(int);
    getsockopt(sockfd, IPPROTO_IP, CMD_ALT_RULE, &res, &res_len);

    if(res == 1){
        printf("Modify rule %d successfully!\n", target_id);
    }else if(res ==0)
    {
        printf("Rule %d does not exists.\n", target_id);
    }else if (res == 2)
    {
        printf("Rule already exists.\n");
    }
    
}

void setRuleStat(int sockfd, int rule_id, int active){  //屏蔽规则
    RuleStat* rule_stat = malloc(sizeof(RuleStat));
    rule_stat->rule_id = rule_id;
    if(!active){
        rule_stat->blocked = 1;
    }else{
        rule_stat->blocked = 0;
    }
    setsockopt(sockfd, IPPROTO_IP, CMD_RULE_STATE, rule_stat, sizeof(RuleStat));
    free(rule_stat);

    int var_len = sizeof(int);
    int* res=malloc(var_len);
    getsockopt(sockfd, IPPROTO_IP, CMD_RULE_STATE, res, &var_len);
    if(*res){
        printf("Changed rule %d to %s.\n", rule_id, (active) ? "active": "blocked");
    }else{
        printf("Change rule %d failed!\n", rule_id);
    }
}

void showDebugState(int sockfd){            //展示debug_level
    int val_len = sizeof(int);
    int *val = malloc(val_len);
    getsockopt(sockfd, IPPROTO_IP, CMD_GET_DEBUG_STATE, val, &val_len);
    printf("Debug state: %d\n", *val);
}

void setDebugState(int sockfd, int state){
    setsockopt(sockfd, IPPROTO_IP, CMD_SET_DEBUG_STATE, &state, sizeof(state));
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

unsigned int str2ICMP_type(char* ICMP_type)
{
	unsigned int type = -1;
	if(!strcmp(ICMP_type,"any")||!strcmp(ICMP_type,"None")) type = -1;//0表示任何子类型或非ICMP协议报文
	else type = atoi(ICMP_type);

	return type;
}

void str2mac(char* r_mac, const char* getmac)       //转换格式
{
    char* any = "any";
    if(!strcmp(getmac,"any"))
    {
        strcpy(r_mac, getmac);
    }
    else
    {
        strcpy(r_mac, getmac);
    }
}


void showUsage(){
    printf("Supported commands:\n");
    printf("sudo ./cmdtool rule [add/del/alt/show/set] [args]:\n");     
    printf("add: add a new rule. Supported args: -m dip -n dport -x sip -y sport -i indev_mac -o outdev_mac -t ICMP_type, with default value: any.\n");
    printf("del: delete rules by given id. Supported args: ids.\n");
    printf("alt: change a existing rule. Supported args is the same as add.\n");        
    printf("show: show all rules. No args.\n");
    printf("set: block rule.\n");
    printf("sudo ./cmdtool debug [show/set]:\n");
    printf("show: show debug info. No args.\n");
    printf("set: set debug_level. Debug level can be 0 or 1.\n");

}
