#include <stdio.h>  
#include <sys/time.h>  
#include <time.h>  
#include<stdlib.h>  
#include <sys/time.h>  
#include <time.h>  
//#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/*void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    struct ip *iph;
    struct tcphdr *tcph;
    struct timeval timestamp;

    // 获取时间戳信息
    timestamp = pkthdr->ts;

    // 解析IP头部
    iph = (struct ip *)(packet + 14); // 偏移14字节，以跳过以太网头部
    // 获取TCP头部
    tcph = (struct tcphdr *)(packet + 14 + iph->ip_hl * 4); // 偏移14字节+IP头部长度

    // 打印时间戳和其他信息
    printf("Packet sent at: %ld.%06ld\n", timestamp.tv_sec, timestamp.tv_usec);
    printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));
    printf("Source Port: %d\n", ntohs(tcph->th_sport));
    printf("Destination Port: %d\n", ntohs(tcph->th_dport));
}*/



int gettimeofday(struct timeval *tv, struct timezone *tz);  
int comparetime(struct tm *time_min, struct tm *time_max) //比较时间是否在范围内
{  
struct timeval tv;
struct tm *area;
	gettimeofday(&tv,0);
	area = localtime(&(tv.tv_sec));
        printf("%d-%02d-%02d %02d:%02d:%02d\n", area->tm_year + 1900, area->tm_mon + 1, area->tm_mday, area->tm_hour, area->tm_min, area->tm_sec);
	if(60*(24*(30*(12*(area->tm_year+1900-2020)+area->tm_mon)+area->tm_mday-1)+area->tm_hour-1)+area->tm_min>=
	60*(24*(30*(12*(time_min->tm_year+1900-2020)+time_min->tm_mon)+time_min->tm_mday-1)+time_min->tm_hour-1)+time_min->tm_min&&
	60*(24*(30*(12*(area->tm_year+1900-2020)+area->tm_mon)+area->tm_mday-1)+area->tm_hour-1)+area->tm_min<=
	60*(24*(30*(12*(time_max->tm_year+1900-2020)+time_max->tm_mon)+time_max->tm_mday-1)+time_max->tm_hour-1)+time_max->tm_min)
	{
	  return 1;
	}
	else return 0;
}

//转换输入时间
void exchange(char *intime,struct tm *time_min,struct tm *time_max)//时间输入格式为xxxx(年)-xx(月)-xx(日)-xx(时)-xx(分)-xxxx(年)-xx(月)-xx(日)-xx(时)-xx(分)
{
     char *temp;
     int i;   
     if(intime=="any") time_min->year=-1;
     else
     {
     for(i=0;i<=3;i++){ temp[i]=intime[i];}
     time_min->tm_year=atoi(temp)-1900;
     temp[2]='\0';temp[3]='\0';
     for(i=5;i<=6;i++) {temp[i-5]=intime[i]; }
     time_min->tm_mon=atoi(temp)-1;
     for(i=8;i<=9;i++) {temp[i-8]=intime[i]; }
     time_min->tm_mday=atoi(temp);
     for(i=11;i<=12;i++) {temp[i-11]=intime[i]; }
     time_min->tm_hour=atoi(temp);
     for(i=14;i<=15;i++) {temp[i-14]=intime[i]; }
     time_min->tm_min=atoi(temp);
     for(i=17;i<=20;i++){ temp[i-17]=intime[i];}
     time_max->tm_year=atoi(temp)-1900;
     temp[2]='\0';temp[3]='\0';
     for(i=22;i<=23;i++) {temp[i-22]=intime[i]; }
     time_max->tm_mon=atoi(temp)-1;
     for(i=25;i<=26;i++) {temp[i-25]=intime[i]; }
     time_max->tm_mday=atoi(temp);
     for(i=28;i<=29;i++) {temp[i-28]=intime[i]; }
     time_max->tm_hour=atoi(temp);
     for(i=31;i<=32;i++) {temp[i-31]=intime[i]; }
     time_max->tm_min=atoi(temp);
     }
}
