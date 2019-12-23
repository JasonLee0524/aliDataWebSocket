#ifndef __ALIWEBDLL__
#define __ALIWEBDLL__

#define MAX_PARAM_NAME_LENGTH                   64                  /* 属性或事件名的最大长度*/
#define MAX_PARAM_VALUE_LENGTH                  2048                /* 属性值或事件参数的最大长度*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERR,
    LOG_LEVEL_NONE,
} LOG_LEVEL;


/** 创建线程 */
typedef char(*UWebThreadCreate) (void** handle,void *(*vm_task)(void*), void *pArg);
/** 释放线程 */
typedef void(*UWebThreadDelete)(void* handle);
/** 创建互斥锁 */
typedef void*(*UWebMutexNew)(void);
/** 加锁互斥锁 */
typedef void(*UWebMutexLock)(void* pMutex);
/** 解锁互斥锁 */
typedef void(*UWebMutexUnlock)(void* pMutex);
/** 释放互斥锁 */
typedef void(*UWebMutexFree)(void* pMutex);
/** 创建信号量 */
typedef void*(*UWebSemaphoreNew)(void);
/** 加锁信号量 */
typedef void(*UWebSemaphorePost)(void* sem);
/** 信号量等待 */
typedef int(*UWebSemaphoreWait)(void* sem,int timeout_ms);
/** 释放信号量 */
typedef void(*UWebSemaphoreFree)(void* sem);
/** 获取当前主机的时间 */
typedef int(*UWebptimeMs)(void);
/** 动态内存申请 */
typedef void* (*UWebMalloc)(unsigned int iSize);
/** 动态内存释放 */
typedef void(*UWebFree)(void* pMemory);
//睡眠ms
typedef void(*UWebSleepMS)(unsigned int  ms);
//随机数
typedef int(*UWebRandom)(unsigned int  region);


typedef struct _common_func{
	UWebThreadCreate        utc_thread_create;        /**< 创建线程 */
    UWebThreadDelete        utc_thread_delete;        /**< 释放线程 */
	UWebMutexNew       utc_mutex_new;                    /**< 创建互斥锁 */
	UWebMutexLock      utc_mutex_lock;                   /**< 加锁互斥锁 */
	UWebMutexUnlock    utc_mutex_unlock;           /**< 解锁互斥锁 */
	UWebMutexFree      utc_mutex_free;                     /**< 释放互斥锁 */
    UWebSemaphoreNew  utc_semaphore_new;   /** 创建信号量 */
    UWebSemaphorePost  utc_semaphore_post;   /** 加锁信号量 */
    UWebSemaphoreWait  utc_semaphore_wait;   /** 信号量等待 */
    UWebSemaphoreFree  utc_semaphore_free;     /** 释放信号量 */
	UWebMalloc         utc_malloc;                                      /**< 内存申请 */
	UWebFree             utc_free;                                               /**< 内存释放 */
    UWebptimeMs    utc_uptimems;                                /**< 获取时间 */
    UWebSleepMS    utc_sleepms;
    UWebRandom    utc_random;
}common_func;

typedef enum leda_conn_state
{
    LEDA_WS_CONNECTED = 0,
    LEDA_WS_DISCONNECTED
} leda_conn_state_e;

typedef void (*conn_state_change_callback)(leda_conn_state_e state, void *usr_data);

typedef struct ws_conn_cb
{
    /* 连接状态的回调函数
     * 1. 连接成功, 上线设备
     * 2. 连接断开, 下线设备待重新连接成功再上线
    */
    conn_state_change_callback conn_state_change_cb;

    /*连接状态变更回调函数的用户数据*/
    void *usr_data;
} ws_conn_cb_t;

typedef enum leda_data_type
{
    LEDA_TYPE_INT = 0,                                              /* 整型 */
    LEDA_TYPE_BOOL,                                                 /* 布尔型 对应值为0 or 1*/
    LEDA_TYPE_FLOAT,                                                /* 浮点型 */
    LEDA_TYPE_TEXT,                                                 /* 字符串型 */
    LEDA_TYPE_DATE,                                                 /* 日期型 */
    LEDA_TYPE_ENUM,                                                 /* 枚举型 */
    LEDA_TYPE_STRUCT,                                               /* 结构型 */
    LEDA_TYPE_ARRAY,                                                /* 数组型 */
    LEDA_TYPE_DOUBLE,                                               /* 双精浮点型 */

    LEDA_TYPE_BUTT
} leda_data_type_e;

typedef struct leda_device_data
{
    leda_data_type_e    type;                                       /* 值类型, 需要跟设备 物模型 中保持一致 */  
    char                key[MAX_PARAM_NAME_LENGTH];                 /* 属性或事件名 */
    char                value[MAX_PARAM_VALUE_LENGTH];              /* 属性值 */
} leda_device_data_t;


/*
 * 获取属性的回调函数, LinkEdge 需要获取某个设备的属性时, SDK 会调用该接口间接获取到数据并封装成固定格式后回传给 LinkEdge.
 * 开发者需要根据设备id和属性名找到设备, 将属性值获取并以@device_data_t格式返回.
 *
 * @product_key:                 LinkEdge 需要获取属性的具体某个设备所属的ProductKey.
 * @device_name:                 LinkEdge 需要获取属性的具体某个设备的DeviceName.
 * @properties:         开发者需要将属性值更新到properties中.
 * @properties_count:   属性个数.
 * @usr_data:           客户端初始化时, 用户传递的私有数据.
 * 所有属性均获取成功则返回LE_SUCCESS, 其他则返回错误码(参考错误码宏定义).
 * 
 */
typedef int (*get_properties_callback)(const char *product_key,
                                       const char *device_name,
                                       leda_device_data_t properties[],
                                       int properties_count,
                                       void *usr_data);


/*
 * 设置属性的回调函数, LinkEdge 需要设置某个设备的属性时, SDK 会调用该接口将具体的属性值传递给应用程序, 开发者需要在本回调
 * 函数里将属性设置到设备.
 *
 * @product_key:                 LinkEdge 需要设置属性的具体某个设备所属的ProductKey.
 * @device_name:                 LinkEdge 需要设置属性的具体某个设备的DeviceName.
 * @properties:         LinkEdge 需要设置的设备的属性名和值.
 * @properties_count:   属性个数.
 * @usr_data:           客户端初始化时, 用户传递的私有数据.
 * 
 * 若获取成功则返回LE_SUCCESS, 失败则返回错误码(参考错误码宏定义).
 * 
 */
typedef int (*set_properties_callback)(const char *product_key,
                                       const char *device_name,
                                       const leda_device_data_t properties[],
                                       int properties_count,
                                       void *usr_data);


/*
 * 服务调用的回调函数, LinkEdge 需要调用某个设备的服务时, SDK 会调用该接口将具体的服务参数传递给应用程序, 开发者需要在本回调
 * 函数里调用具体的服务, 并将服务返回值按照设备 物模型 里指定的格式返回. 
 *
 * @product_key:           LinkEdge 需要调用服务的具体某个设备所属的ProductKey.
 * @device_name:           LinkEdge 需要调用服务的具体某个设备的DeviceName.
 * @service_name: LinkEdge 需要调用的设备的具体某个服务名.
 * @data:         LinkEdge 需要调用的设备的具体某个服务参数, 参数与设备 物模型 中保持一致.
 * @data_count:   LinkEdge 需要调用的设备的具体某个服务参数个数.
 * @output_data:  开发者需要将服务调用的返回值, 按照设备 物模型 中规定的服务格式返回到output中.
 * @usr_data:     客户端初始化时, 用户传递的私有数据.
 * 
 * 若获取成功则返回LE_SUCCESS, 失败则返回错误码(参考错误码宏定义).
 * */
typedef int (*call_service_callback)(const char *product_key,
                                     const char *device_name,
                                     const char *service_name,
                                     const leda_device_data_t data[],
                                     int data_count,
                                     leda_device_data_t output_data[],
                                     void *usr_data);

/*
 * 上报属性及事件的应答回调函数
 * 上报消息发送成功立马返回, 如果需要上报消息响应值, 需要注册该接口, msg_id对应上报接口的msg_id
 * 
 * @msg_id      消息id
 * @code        上报结果返回码
 * @usr_data    客户端初始化时, 用户传递的私有数据.
 * */
typedef int (*report_reply_callback)(unsigned int msg_id, int code, void *usr_data);

/*
 * 设备回调函数group
*/
typedef struct leda_device_callback
{
    get_properties_callback     get_properties_cb;          /* 设备属性获取回调 */
    void *usr_data_get_property;                            /* 获取属性回调函数的用户私有数据, 在接口被调用时, 该数据会传递过去 */

    set_properties_callback     set_properties_cb;          /* 设备属性设置回调 */
    void *usr_data_set_property;                            /* 设置属性回调函数的用户私有数据, 在接口被调用时, 该数据会传递过去*/

    call_service_callback       call_service_cb;            /* 设备服务回调 */
    int                         service_output_max_count;   /* 设备服务回调结果数组最大长度 */   
    void *usr_data_call_service;                            /* 服务回调函数的用户私有数据, 在接口被调用时, 该数据会传递过去*/

    report_reply_callback       report_reply_cb;            /* 异步上报属性及事件的应答回调函数*/
    void *usr_data_report_reply;                            /* 异步上报属性及事件的应答回调函数的私有数据，在接口被调用时，该数据会传递过去*/
} leda_device_callback_t;


typedef struct leda_conn_info
{
    const char                  *server_ip;         /* WebSocket驱动监听地址 */
    unsigned short int          server_port;        /* WebSocket驱动监听端口 */
    int                         use_tls;            /* 是否使用tls加密, 0不使用, 1使用 */

    const char                  *ca_path;           /* 根证书绝对路径 */
    const char                  *cert_path;         /* 公钥证书绝对路径 */
    const char                  *key_path;          /* 私钥证书绝对路径 */
    int                         timeout;            /* 连接超时时间，单位为秒. 如果设备和Linkedge之间, 在timeout时间内没有数据传输, 连接会被重置 */

    ws_conn_cb_t                ws_conn_cb;         /*websocket连接变更回调*/

    leda_device_callback_t      conn_devices_cb;    /*连接下所有设备的回调函数*/
} leda_conn_info_t;



/*
 * 初始化.
 *
 * @info: 连接信息.
 * 阻塞接口, 成功返回LE_SUCCESS, 失败返回错误码.
 */
extern int leda_init(const leda_conn_info_t *info);

/*
 * 退出.
 *
 * 退出前, 释放资源.
 *
 * 阻塞接口.
 */
extern void leda_exit(void);

/*
 * 上线设备, 设备只有上线后, 才能被 LinkEdge 识别.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口,成功返回LE_SUCCESS, 失败返回错误码.
 */
extern int leda_online(const char *product_key, const char *device_name);

/*
 * 下线设备, 假如设备工作在不正常的状态或设备退出前, 可以先下线设备, 这样LinkEdge就不会继续下发消息到设备侧.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口, 成功返回LE_SUCCESS,  失败返回错误码.
 *
 */
extern int leda_offline(const char *product_key, const char *device_name);

/*
 * 上报事件, 设备具有的事件上报能力在设备 物模型 里有约定.
 *
 * 
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 * @event_name:  事件名称.
 * @data:        @leda_device_data_t, 事件参数数组.
 * @data_count:  事件参数数组长度.
 * @msg_id:      请求消息id, 消息发送成功后会生成消息id, 如果关心请求消息响应结果, 则保存该值, 否则只需要置空NULL即可
 *
 * 非阻塞接口, 等待服务端返回, 成功返回LE_SUCCESS,  失败返回错误码.
 *
 */
extern int leda_report_event(const char *product_key, const char *device_name, const char *event_name, const leda_device_data_t data[], int data_count, unsigned int *msg_id);

/*
 * 上报属性, 设备具有的属性在设备能力描述 物模型 里有规定.
 *
 * 上报属性, 可以上报一个, 也可以多个一起上报.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 * @properties:           @leda_device_data_t, 属性数组.
 * @properties_count:     本次上报属性个数.
 * @msg_id:               请求消息id, 消息发送成功后会生成消息id, 如果关心请求消息响应结果, 则保存该值, 否则只需要置空NULL即可
 *
 * 非阻塞接口, 发送成功即返回, 成功返回LE_SUCCESS,  失败返回错误码.
 *
 */
extern int leda_report_properties(const char *product_key, const char *device_name, const leda_device_data_t properties[], int properties_count, unsigned int *msg_id);

//获取web是否连接的标识
 extern int get_con_status();

 extern  void set_log_level(LOG_LEVEL lvl);

 //注册系统回调接口
extern char register_init(common_func model);
//版本号
extern char* get_version();

/****************************************************************************************************************************/
/*******************websocket的基础API，如果不想用ali数据格式，可以直接调用这些接口完成websocket的通讯****************/
/**************************不过注册函数register_init()还是调用，并必须实现sleepms,malloc,free，3个回调*******************/
/****************************************************************************************************************************/
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
extern int web_socket_client_link_to_server(char *ip, int port, char *interface_path);
 
// server回复client的http请求
extern int web_socket_server_link_to_client(int fd, char *recvBuf, unsigned int bufLen);

 
extern int web_socket_send(int fd, unsigned char *data, unsigned int dataLen, char mod, Websocket_CommunicationType type);
extern int web_socket_recv(int fd, unsigned char *data, unsigned int dataMaxLen);
 
extern void delayms(unsigned int ms);

#endif