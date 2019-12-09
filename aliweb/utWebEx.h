#ifndef __UTWEBEX_H__
#define __UTWEBEX_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "os/aliweb_os.h"
 
// 连接服务器
#define REPORT_LOGIN_CONNECT_TIMEOUT      1000                                                                       // 登录连接超时设置 1000ms
#define REPORT_LOGIN_RESPOND_TIMEOUT      (1000 + REPORT_LOGIN_CONNECT_TIMEOUT)    // 登录等待回应超时设置 1000ms
// 指令发收
#define REPORT_ANALYSIS_ERR_RESEND_DELAY    500     // 接收到回复内容但解析不通过, 延时 一段时间后重发指令      单位ms
// 生成握手key的长度
#define WEBSOCKET_SHAKE_KEY_LEN     16

// websocket根据data[0]判别数据包类型    比如0x81 = 0x80 | 0x1 为一个txt类型数据包
typedef enum{
    WCT_MINDATA = -20,      // 0x0：标识一个中间数据包
    WCT_TXTDATA = -19,      // 0x1：标识一个txt类型数据包
    WCT_BINDATA = -18,      // 0x2：标识一个bin类型数据包
    WCT_DISCONN = -17,      // 0x8：标识一个断开连接类型数据包
    WCT_PING = -16,     // 0x8：标识一个断开连接类型数据包
    WCT_PONG = -15,     // 0xA：表示一个pong类型数据包
    WCT_ERR = -1,
    WCT_NULL = 0
}Websocket_CommunicationType;

// client向server发送http连接请求, 并处理返回
int web_socket_client_link_to_server(char *ip, int port, char *interface_path);
 
// server回复client的http请求
int web_socket_server_link_to_client(int fd, char *recvBuf, unsigned int bufLen);

 
int web_socket_send(int fd, unsigned char *data, unsigned int dataLen, char mod, Websocket_CommunicationType type);
int web_socket_recv(int fd, unsigned char *data, unsigned int dataMaxLen);
 
void delayms(unsigned int ms);




#endif