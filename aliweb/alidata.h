#ifndef __ALIWEB_H__
#define __ALIWEB_H__

#include "base-utils.h"
#include "le_error.h"
#include "log.h"
#include "cJSON.h"
#include "utWebEx.h"
#include "aliwebdll.h"

typedef struct parsed_msg
{
    int     msg_type;
    int     msg_id;
    int     code;
    char    method[16];
    cJSON   *payload;
} parsed_msg_t;


typedef struct ws_msg_reply
{
    struct ut_list_head    list_node;
    int                 msg_id;
    int                 code;
    char                *payload;
    void*                sem;    //信号量 
} ws_msg_reply_t;

typedef enum ws_msg_type
{
    MSG_INVALID = -1,
    MSG_RSP = 0,
    MSG_METHOD
} ws_msg_type_e;

//注册系统回调接口
 char register_init(common_func model);
//版本号
 char* get_version();
/*
 * 初始化.
 *
 * @info: 连接信息.
 * 阻塞接口, 成功返回LE_SUCCESS, 失败返回错误码.
 */
int leda_init(const leda_conn_info_t *info);

/*
 * 退出.
 *
 * 退出前, 释放资源.
 *
 * 阻塞接口.
 */
void leda_exit(void);

/*
 * 上线设备, 设备只有上线后, 才能被 LinkEdge 识别.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口,成功返回LE_SUCCESS, 失败返回错误码.
 */
int leda_online(const char *product_key, const char *device_name);

/*
 * 下线设备, 假如设备工作在不正常的状态或设备退出前, 可以先下线设备, 这样LinkEdge就不会继续下发消息到设备侧.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口, 成功返回LE_SUCCESS,  失败返回错误码.
 *
 */
int leda_offline(const char *product_key, const char *device_name);

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
int leda_report_event(const char *product_key, const char *device_name, const char *event_name, const leda_device_data_t data[], int data_count, unsigned int *msg_id);

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
int leda_report_properties(const char *product_key, const char *device_name, const leda_device_data_t properties[], int properties_count, unsigned int *msg_id);

int get_con_status();
#endif