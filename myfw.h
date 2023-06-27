#define CMD_MIN		0x6000//十进制：24576
 
#define CMD_DEBUG	    CMD_MIN+1
#define CMD_RULE	    CMD_MIN+2
#define CMD_RULE_DEL    CMD_MIN+3
 
#define CMD_MAX		0x6100//十进制：24832
 
#define MYFW_ICMP   1  //IPPROTO_ICMP
#define MYFW_TCP    6  //IPPROTO_TCP
#define MYFW_UDP    17 //IPPROTO_UDP
 
typedef struct{
    unsigned int sip;//信息来源ip地址
    unsigned int dip;//信息目的ip地址
    unsigned short sport;//信息的发出端口
    unsigned short dport;//发送信息的目的端口
    unsigned short protocol;//使用的协议
    unsigned short allow;//是否接收信息
}Rule;
 
typedef struct{
    unsigned int count;//表示规则的个数
    Rule rule;//保存规则
}RuleTable;