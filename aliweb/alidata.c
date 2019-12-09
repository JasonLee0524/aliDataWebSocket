#include "alidata.h"


#define LOG_TAG                 "LINKEDGE_DEVICE_ACCESS"

#define METHOD_ONLINE           "onlineDevice"
#define METHOD_OFFLINE          "offlineDevice"

#define EMTHOD_REPORT_PROPERTY  "reportProperty"
#define METHOD_REPORT_EVENT     "reportEvent"

#define METHOD_CALL_SERVICE     "callService"
#define METHOD_GET_PROPERTY     "getProperty"
#define METHOD_SET_PROPERTY     "setProperty"

#define CONN_PROTOCOL           "alibaba-iot-linkedge-protocol"
#define PROTOCOL_VERSION        "1.0"


UT_LIST_HEAD(g_ws_msg_reply_list);
//pthread_mutex_t g_ws_msg_reply_lock; //线程锁
void* g_ws_msg_reply_lock = NULL;
void* g_pthreadhandle;
static ws_conn_cb_t             g_conn_cb = {0};
static leda_device_callback_t   g_devs_cb = {0};

static int              g_has_init       = 0;
static int              g_conn_state     = -1;
static int              g_fd = -1;

static unsigned int     g_msg_id         = 0;

static void*  g_msg_locker     = NULL;

static char *g_type_map[LEDA_TYPE_BUTT + 1] = 
{
    "int",    //LEDA_TYPE_INT
    "bool",   //LEDA_TYPE_BOOL
    "float",  //LEDA_TYPE_FLOAT
    "text",   //LEDA_TYPE_TEXT
    "date",   //LEDA_TYPE_DATE
    "enum",   //LEDA_TYPE_ENUM
    "struct", //LEDA_TYPE_STRUCT
    "array",  //LEDA_TYPE_ARRAY
    "double", //LEDA_TYPE_DOUBLE
    "invalid"
};

const char *type_number_to_string(int type)
{
    if (type < LEDA_TYPE_INT || type >= LEDA_TYPE_BUTT)
    {
        log_w(LOG_TAG,"unknown data type: %d\n", type);
        return g_type_map[LEDA_TYPE_BUTT];
    }

    return g_type_map[type];
}

int type_string_to_number(char *type)
{
    if (0 == strcmp("int", type))
    {
        return LEDA_TYPE_INT;
    }
    else if (0 == strcmp("bool", type))
    {
        return LEDA_TYPE_BOOL;
    }
    else if (0 == strcmp("float", type))
    {
        return LEDA_TYPE_FLOAT;
    }
    else if (0 == strcmp("text", type))
    {
        return LEDA_TYPE_TEXT;
    }
    else if (0 == strcmp("date", type))
    {
        return LEDA_TYPE_DATE;
    }
    else if (0 == strcmp("enum", type))
    {
        return LEDA_TYPE_ENUM;
    }
    else if (0 == strcmp("struct", type))
    {
        return LEDA_TYPE_STRUCT;
    }
    else if (0 == strcmp("array", type))
    {
        return LEDA_TYPE_ARRAY;
    }
    else if (0 == strcmp("double", type))
    {
        return LEDA_TYPE_DOUBLE;
    }

    log_w(LOG_TAG, "unknown data type: %s\n", type);

    return LEDA_TYPE_BUTT;
}

cJSON *struct_data_to_json_data(const leda_device_data_t *struct_data, int data_cnt)
{
    int     i           = 0;
    cJSON   *root       = NULL;
    cJSON   *item       = NULL;
    cJSON   *sub_item   = NULL;

    root = cJSON_CreateArray();
    if (NULL == root)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return NULL;
    }

    for (i = 0; i < data_cnt; i++)
    {
        item = cJSON_CreateObject();
        if (NULL == item)
        {
            log_w(LOG_TAG, "no memory can allocate\n");
            cJSON_Delete(root);
            return NULL;
        }

        cJSON_AddStringToObject(item, "identifier", struct_data[i].key);
        cJSON_AddStringToObject(item, "type", type_number_to_string(struct_data[i].type));

        switch (struct_data[i].type)
        {
        case LEDA_TYPE_INT:
        case LEDA_TYPE_BOOL:
        case LEDA_TYPE_ENUM:
            cJSON_AddNumberToObject(item, "value", atoi(struct_data[i].value));
            break;
        case LEDA_TYPE_DOUBLE:
        case LEDA_TYPE_FLOAT:
            cJSON_AddNumberToObject(item, "value", atof(struct_data[i].value));
            break;
        case LEDA_TYPE_DATE:
        case LEDA_TYPE_TEXT:
            cJSON_AddStringToObject(item, "value", struct_data[i].value);
            break;
        case LEDA_TYPE_ARRAY:
        case LEDA_TYPE_STRUCT:
            sub_item = cJSON_Parse(struct_data[i].value);
            if (!sub_item)
            {
                log_w(LOG_TAG, "identifier: %s value: %s is invalid json format\n", struct_data[i].key, struct_data[i].value);
                cJSON_Delete(root);
                return NULL;
            }
            cJSON_AddItemToObject(item, "value", sub_item);
            break;
        default:
            log_w(LOG_TAG, "identifier: %s type: %s is invalid type\n", struct_data[i].key, struct_data[i].type);
            cJSON_AddStringToObject(item, "value", "invalid");
            break;
        }

        cJSON_AddItemToArray(root, item);
    }

    return root;
}

int json_data_to_struct_data(cJSON *json_data, leda_device_data_t **struct_data, int *data_cnt)
{
    int     size        = 0;
    int     i           = 0;
    cJSON   *item       = NULL;
    cJSON   *sub_item   = NULL;
    char    *buff       = NULL;

    leda_device_data_t *data = NULL;

    size = cJSON_GetArraySize(json_data);
    if (size <= 0)
    {
        *data_cnt = 0;
        return LE_SUCCESS;
    }

    *data_cnt = size;
    data = utc_malloc(sizeof(leda_device_data_t) * size);
    if (NULL == data)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    cJSON_ArrayForEach(item, json_data)
    {
        if (item->type == cJSON_String)
        {
            snprintf(data[i++].key, MAX_PARAM_NAME_LENGTH, "%s", item->valuestring);
            continue;
        }

        sub_item = cJSON_GetObjectItem(item, "identifier");
        if (NULL == sub_item)
        {
            utc_free(data);
            return LE_ERROR_INVAILD_PARAM;
        }
        snprintf(data[i].key, MAX_PARAM_NAME_LENGTH, "%s", sub_item->valuestring);

        sub_item = cJSON_GetObjectItem(item, "type");
        if (NULL == sub_item || sub_item->type != cJSON_String)
        {
            utc_free(data);
            return LE_ERROR_INVAILD_PARAM;
        }
        data[i].type = type_string_to_number(sub_item->valuestring);

        sub_item = cJSON_GetObjectItem(item, "value");
        if (NULL == sub_item)
        {
            utc_free(data);
            return LE_ERROR_INVAILD_PARAM;
        }

        switch (data[i].type)
        {
        case LEDA_TYPE_INT:
        case LEDA_TYPE_BOOL:
        case LEDA_TYPE_ENUM:
            snprintf(data[i].value, MAX_PARAM_VALUE_LENGTH, "%d", sub_item->valueint);
            break;
        case LEDA_TYPE_FLOAT:
        case LEDA_TYPE_DOUBLE:
            snprintf(data[i].value, MAX_PARAM_VALUE_LENGTH, "%lf", sub_item->valuedouble);
            break;
        case LEDA_TYPE_TEXT:
        case LEDA_TYPE_DATE:
            snprintf(data[i].value, MAX_PARAM_VALUE_LENGTH, "%s", sub_item->valuestring);
            break;
        case LEDA_TYPE_STRUCT:
        case LEDA_TYPE_ARRAY:
            buff = cJSON_PrintUnformatted(sub_item);
            if (!buff)
            {
                log_w(LOG_TAG, "no memory can allocate\n");
                utc_free(data);
                return LE_ERROR_ALLOCATING_MEM;
            }
            snprintf(data[i].value, MAX_PARAM_VALUE_LENGTH, "%s", buff);
            cJSON_free(buff);
            break;
        default:
            log_w(LOG_TAG, "identifier: %s type: %s is invalid type\n", data[i].key, data[i].type);
            break;
        }

        ++i;
    }
    *struct_data = data;

    return LE_SUCCESS;
}

static unsigned int _ws_get_msg_id()
{
    if(g_msg_locker == NULL){
       g_msg_locker = utc_mutex_create();
    }
    utc_mutex_lock(g_msg_locker);
    
    ++g_msg_id;
    utc_mutex_unlock(g_msg_locker);

    return g_msg_id;
}

static ws_msg_reply_t *_ws_get_reply_by_msg_id(int msg_id)
{
    ws_msg_reply_t *pos     = NULL;
    ws_msg_reply_t *next    = NULL;
    ws_msg_reply_t *reply   = NULL;

    if(g_ws_msg_reply_lock == NULL){
       g_ws_msg_reply_lock = utc_mutex_create();
    }
    utc_mutex_lock(g_ws_msg_reply_lock);
    ut_list_for_each_entry_safe(pos, next, &g_ws_msg_reply_list, list_node)
    {
        if (pos->msg_id == msg_id)
        {
            reply = pos;
            break;
        }
    }
    utc_mutex_unlock(g_ws_msg_reply_lock);

    return reply;
}


static int _ws_insert_reply(int msg_id)
{
    ws_msg_reply_t *reply = NULL;

    utc_mutex_lock(g_ws_msg_reply_lock);
    reply = (ws_msg_reply_t *)utc_malloc(sizeof(ws_msg_reply_t));
    if (NULL == reply)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        utc_mutex_unlock(g_ws_msg_reply_lock);
        return LE_ERROR_ALLOCATING_MEM;
    }

    memset(reply, 0, sizeof(ws_msg_reply_t));
    reply->sem =utc_semaphore_create();
    if (reply->sem == NULL)
    {
        utc_free(reply);
        log_w(LOG_TAG, "semphore init failed\n");
        utc_mutex_unlock(g_ws_msg_reply_lock);
        return LE_ERROR_UNKNOWN;
    }

    reply->msg_id = msg_id;
    reply->code = LE_ERROR_UNKNOWN;

    ut_list_add(&reply->list_node, &g_ws_msg_reply_list);
    utc_mutex_unlock(g_ws_msg_reply_lock);

    return LE_SUCCESS;
}

static void _ws_remove_reply(int msg_id)
{
    ws_msg_reply_t *reply = NULL;

    reply = _ws_get_reply_by_msg_id(msg_id);
    if (NULL == reply)
    {
        log_w(LOG_TAG, "It's no exist that msg id %d in request msg list\n", msg_id);
        return;
    }

    utc_mutex_lock(g_ws_msg_reply_lock);
    if (NULL != reply->payload)
    {
        utc_free(reply->payload);
        reply->payload = NULL;
    }
    utc_semaphore_destroy(reply->sem);
    ut_list_del(&reply->list_node);
    utc_free(reply);
    utc_mutex_unlock(g_ws_msg_reply_lock);
    return;
}

static int _ws_set_reply_result(int msg_id, int code, char *payload)
{
    ws_msg_reply_t *reply = NULL;

    reply = _ws_get_reply_by_msg_id(msg_id);
    if (NULL == reply)
    {
        return LE_ERROR_UNKNOWN;
    }
    utc_mutex_lock(g_ws_msg_reply_lock);
    reply->code = code;
    if (NULL != payload)
    {
        reply->payload = utc_malloc(strlen(payload));
        memcpy(reply->payload,payload,strlen(payload));
    }
    utc_mutex_unlock(g_ws_msg_reply_lock);

    utc_semaphore_post(reply->sem);

    return LE_SUCCESS;
}

static int _ws_get_reply_result(int msg_id, int timeout_ms, int *code, char **payload)
{
    int             ret     = 0;
    ws_msg_reply_t  *reply  = NULL;

    reply = _ws_get_reply_by_msg_id(msg_id);
    if (NULL == reply)
    {
        log_w(LOG_TAG, "It's no exist that msg id %d in request msg list\n", msg_id);
        return LE_ERROR_INVAILD_PARAM;
    }

    ret = utc_semaphore_wait(reply->sem, 30);
    if (-1 == ret)
    {
        _ws_remove_reply(msg_id);
        log_w(LOG_TAG, "It's time out that get reply from request msg id %d", msg_id);
        return LE_ERROR_TIMEOUT;
    }

    if (NULL != code)
    {
        *code = reply->code;
    }

    if (NULL != payload)
    {
        *payload = strdup(reply->payload);
    }

    _ws_remove_reply(msg_id);

    return LE_SUCCESS;
}

int leda_send_rsp(int code, int msg_id, cJSON *payload)
{
    cJSON   *root   = NULL;
    char    *msg    = NULL;
    int     ret     = LE_SUCCESS;

    root = cJSON_CreateObject();
    if (NULL == root)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    cJSON_AddNumberToObject(root, "code", code);
    cJSON_AddNumberToObject(root, "messageId", msg_id);
    if (NULL == payload)
    {
        payload = cJSON_CreateObject();
        if (NULL == payload)
        {
            log_w(LOG_TAG, "no memory can allocate\n");
            cJSON_Delete(root);
            return LE_ERROR_ALLOCATING_MEM;
        }
    }
    cJSON_AddItemToObject(root, "payload", payload);

    msg = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (NULL == msg)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    log_i(LOG_TAG, "send response msg: %s", msg);
    //ret = wsc_add_msg(msg, strlen(msg) + 1, 0);
    ret = web_socket_send(g_fd, (unsigned char*)msg, strlen(msg)+1, 1, WCT_TXTDATA);
    if( ret >= 0 ){
        ret = LE_SUCCESS;
    }
    cJSON_free(msg);

    return ret;
}

int leda_rsp_get_properties(char *pk, char *dn, int msg_id, leda_device_data_t *data, int data_cnt)
{
    int     ret         = LE_ERROR_UNKNOWN;

    cJSON   *root       = NULL;
    cJSON   *payload    = NULL;
    cJSON   *properties = NULL;

    char    *msg        = NULL;

    payload = cJSON_CreateObject();
    if (NULL == payload)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    if (g_devs_cb.get_properties_cb)
    {
        ret = g_devs_cb.get_properties_cb(pk, dn, data, data_cnt, g_devs_cb.usr_data_get_property);
    }
    else
    {
        log_w(LOG_TAG, "get_properties_cb no hook init!\n");
    }

    if (ret == LE_SUCCESS)
    {
        properties = struct_data_to_json_data(data, data_cnt);
        cJSON_AddItemToObject(payload, "properties", properties);
    }

    return leda_send_rsp(ret, msg_id, payload);
}
int leda_rsp_set_properties(char *pk, char *dn, int msg_id, leda_device_data_t *data, int data_cnt)
{
    int ret = LE_ERROR_UNKNOWN;

    if (g_devs_cb.set_properties_cb)
    {
        ret = g_devs_cb.set_properties_cb(pk, dn, data, data_cnt, g_devs_cb.set_properties_cb);
    }
    else
    {
        log_w(LOG_TAG, "set_properties_cb no hook init!\n");
    }

    return leda_send_rsp(ret, msg_id, NULL);
}
int leda_rsp_call_service(char *pk, char *dn, int msg_id, const char *service_name, leda_device_data_t *input_params,
                          int params_cnt)
{
    int     ret         = LE_ERROR_UNKNOWN;
    int     i           = 0;

    cJSON   *payload    = NULL;
    cJSON   *params     = NULL;

    leda_device_data_t *output_params = NULL;

    output_params = utc_malloc(sizeof(leda_device_data_t) * g_devs_cb.service_output_max_count);
    if (!output_params)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    memset(output_params, 0, sizeof(leda_device_data_t) * g_devs_cb.service_output_max_count);
    if (g_devs_cb.call_service_cb)
    {
        ret = g_devs_cb.call_service_cb(pk, dn, service_name, input_params, params_cnt, output_params, g_devs_cb.usr_data_call_service);
        if (ret != LE_SUCCESS)
        {
            goto end;
        }
    }
    else
    {
        log_w(LOG_TAG, "call_service_cb no hook init!\n");
    }

    params_cnt = 0;
    for (i = 0; i < g_devs_cb.service_output_max_count; i++)
    {
        if (strlen(output_params[i].key) == 0)
        {
            break;
        }
        ++params_cnt;
    }

    payload = cJSON_CreateObject();
    if (NULL == payload)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        goto end;
    }

    params = struct_data_to_json_data(output_params, params_cnt);
    if (NULL != params)
    {
        cJSON_AddItemToObject(payload, "outputData", params);
    }

end:

    if (NULL != output_params)
    {
        utc_free(output_params);
    }

    return leda_send_rsp(ret, msg_id, payload);
}

static void threadpool_recv_proc(void *arg)
{
    parsed_msg_t        *parsed_msg     = NULL;
    char                *payload_str    = NULL;
    char                *pk             = NULL;
    char                *dn             = NULL;;
    cJSON               *item           = NULL;
    cJSON               *service_name   = NULL;
    leda_device_data_t  *data           = NULL;
    int                 data_cnt        = 0;

    parsed_msg = (parsed_msg_t *)arg;
    if (parsed_msg->msg_type == MSG_RSP)
    {
        payload_str = cJSON_PrintUnformatted(parsed_msg->payload);
        if (NULL != payload_str)
        {
            if (LE_SUCCESS != _ws_set_reply_result(parsed_msg->msg_id, parsed_msg->code, payload_str))
            {
                if (g_devs_cb.report_reply_cb)
                {
                    log_i(LOG_TAG, "recive response msg id: %u\n", parsed_msg->msg_id);
                    g_devs_cb.report_reply_cb(parsed_msg->msg_id, parsed_msg->code, g_devs_cb.usr_data_report_reply);
                }
            }
            cJSON_free(payload_str);
        }
    }
    else if (parsed_msg->msg_type == MSG_METHOD)
    {
        item = cJSON_GetObjectItem(parsed_msg->payload, "productKey");
        if (NULL == item)
        {
            log_i(LOG_TAG, "productKey NULL\n");
            goto end;
        }
        pk = item->valuestring;

        item = cJSON_GetObjectItem(parsed_msg->payload, "deviceName");
        if (NULL == item)
        {
            log_i(LOG_TAG, "deviceName NULL\n");
            goto end;
        }
        dn = item->valuestring;

        item = cJSON_GetObjectItem(parsed_msg->payload, "properties");
        if (NULL == item)
        {
            item = cJSON_GetObjectItem(parsed_msg->payload, "inputData");
            if (NULL == item)
            {
                log_i(LOG_TAG, "properties inputData NULL\n");
                goto end;
            }
        }

        if (LE_SUCCESS != json_data_to_struct_data(item, &data, &data_cnt))
        {
             log_i(LOG_TAG, "NO LE_SUCCESS\n");
            goto end;
        }

        if (0 == strcmp(parsed_msg->method, METHOD_GET_PROPERTY))
        {
             log_i(LOG_TAG, "leda_rsp_get_properties\n");
            leda_rsp_get_properties(pk, dn, parsed_msg->msg_id, data, data_cnt);
        }
        else if (0 == strcmp(parsed_msg->method, METHOD_SET_PROPERTY))
        {
             log_i(LOG_TAG, "leda_rsp_set_properties\n");
            leda_rsp_set_properties(pk, dn, parsed_msg->msg_id, data, data_cnt);
        }
        else if (0 == strcmp(parsed_msg->method, METHOD_CALL_SERVICE))
        {
            log_i(LOG_TAG, "leda_rsp_call_service\n");
            service_name = cJSON_GetObjectItem(parsed_msg->payload, "identifier");
            if (NULL == service_name)
            {
                 log_i(LOG_TAG, "identifier NULL\n");
                goto end;
            }
            leda_rsp_call_service(pk, dn, parsed_msg->msg_id, service_name->valuestring, data, data_cnt);
        }
    }

end:
    if (NULL != parsed_msg)
    {
        if (NULL != parsed_msg->payload)
        {
            cJSON_Delete(parsed_msg->payload);
        }

        utc_free(parsed_msg);
    }

    if (NULL != data)
    {
        utc_free(data);
    }
    return;
}

static int leda_parse_receive_msg(cJSON *root, int *msg_id, int *code, char **method, cJSON **payload)
{
    cJSON *item = NULL;

    item = cJSON_GetObjectItem(root, "messageId");
    if ((NULL == item) || (cJSON_Number != item->type))
    {
        log_w(LOG_TAG, "the type of msg id is invalid\n");
        return MSG_INVALID;
    }

    *msg_id = item->valueint;
    *payload = cJSON_GetObjectItem(root, "payload");

    item = cJSON_GetObjectItem(root, "code");
    if (NULL != item)
    {
        if (cJSON_Number != item->type)
        {
            log_w(LOG_TAG, "the type of code is invalid\n");
            return MSG_INVALID;
        }
        *code = item->valueint;
        return MSG_RSP;
    }

    item = cJSON_GetObjectItem(root, "method");
    if ((NULL == item) || (cJSON_String != item->type))
    {
        return MSG_INVALID;
    }
    *method = item->valuestring;

    return MSG_METHOD;
}

static void cb_ws_recv(const char *msg, size_t len, void *user)
{
    cJSON           *root       = NULL;
    cJSON           *payload    = NULL;

    char            *method     = NULL;
    parsed_msg_t    *parsed_msg = NULL;

    if (NULL == msg)
    {
        log_w(LOG_TAG, "receive reply msg is NULL\n");
        return;
    }

    root = cJSON_Parse(msg);
    if (NULL == root)
    {
        log_w(LOG_TAG, "receive reply msg is invalid json format\n");
        return;
    }

    parsed_msg = utc_malloc(sizeof(parsed_msg_t));
    if (NULL == parsed_msg)
    {
        cJSON_Delete(root);
        log_w(LOG_TAG, "no memory can allocate\n");
        return;
    }
    memset(parsed_msg, 0, sizeof(parsed_msg_t));

    parsed_msg->msg_type = leda_parse_receive_msg(root, &parsed_msg->msg_id, &parsed_msg->code, &method, &payload);
    if (NULL != method)
    {
        snprintf(parsed_msg->method, sizeof(parsed_msg->method), "%s", method);
    }

    if (NULL != payload)
    {
        parsed_msg->payload = cJSON_Duplicate(payload, 1);
        if (NULL == parsed_msg->payload)
        {
            log_w(LOG_TAG, "no memory can allocate\n");
            utc_free(parsed_msg);
            cJSON_Delete(root);
            return;
        }
    }
    cJSON_Delete(root);

   // threadpool_add(g_threadpool, threadpool_recv_proc, (void *)parsed_msg, 0);
    threadpool_recv_proc((void *)parsed_msg);

    return;
}

static void cb_ws_close(void *user)
{
    g_conn_state = LEDA_WS_DISCONNECTED;
    log_i(LOG_TAG, "connection failed.\n");

    if (g_conn_cb.conn_state_change_cb)
    {
        g_conn_cb.conn_state_change_cb(LEDA_WS_DISCONNECTED, g_conn_cb.usr_data);
    }

    return;
}

static void cb_ws_estab(void *user)
{
    g_conn_state = LEDA_WS_CONNECTED;
    log_i(LOG_TAG, "connection success.\n");

    if (g_conn_cb.conn_state_change_cb)
    {
        g_conn_cb.conn_state_change_cb(LEDA_WS_CONNECTED, g_conn_cb.usr_data);
    }

    return;
}
int leda_send_method(const char *pk, 
                     const char *dn, 
                     const char *method, 
                     const char *event_name,
                     const leda_device_data_t *data, 
                     int data_cnt)
{
    cJSON           *root       = NULL;
    cJSON           *payload    = NULL;
 
    unsigned int    msg_id      = 0;
    char            *msg        = NULL;

    int             ret         = 0;
    int             code        = 0;

    if (LEDA_WS_CONNECTED != g_conn_state)
    {
        log_w(LOG_TAG, "the connection is disconnected\n");
        return LEDA_ERROR_CONNECTION;
    }

    if (NULL == pk || NULL == dn || NULL == method)
    {
        log_w(LOG_TAG, "pk: %s dn: %s method: %s has invlid value\n", pk, dn, method);
        return LE_ERROR_INVAILD_PARAM;
    }

    root = cJSON_CreateObject();
    if (NULL == root)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    payload = cJSON_CreateObject();
    if (NULL == payload)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        cJSON_Delete(root);
        return LE_ERROR_ALLOCATING_MEM;
    }

    msg_id = _ws_get_msg_id();

    cJSON_AddStringToObject(root, "version", PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, "messageId", msg_id);
    cJSON_AddStringToObject(root, "method", method);

    cJSON_AddItemToObject(root, "payload", payload);
    cJSON_AddStringToObject(payload, "productKey", pk);
    cJSON_AddStringToObject(payload, "deviceName", dn);

    /* 设备上下线 */
    if (0 == strcmp(method, METHOD_ONLINE) || 0 == strcmp(method, METHOD_OFFLINE))
    {
        goto next_step;
    }

next_step:

    msg = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (NULL == msg)
    {
        log_w(LOG_TAG, "no memory can allocate1\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    ret = _ws_insert_reply(msg_id);
    if (ret != LE_SUCCESS)
    {
        log_w(LOG_TAG, "_ws_insert_reply fail\n");
        cJSON_free(msg);
        return ret;
    }

    log_i(LOG_TAG, "send  msg: %s\n", msg);
    ret = web_socket_send(g_fd, (unsigned char*)msg, strlen(msg), 1, WCT_TXTDATA);
    if( ret >= 0 ){
        ret = LE_SUCCESS;
    }
    cJSON_free(msg);
    if (ret != LE_SUCCESS)
    {
        log_w(LOG_TAG, "send timeout1\n");
        _ws_remove_reply(msg_id);
        return ret;
    }

    ret = _ws_get_reply_result(msg_id, 10000, &code, NULL);
    if (ret != LE_SUCCESS)
    {
        return ret;
    }

    return code;
}
int leda_asyn_send_method(const char *pk, 
                          const char *dn, 
                          const char *method, 
                          const char *event_name,
                          const leda_device_data_t *data, 
                          int data_cnt,
                          unsigned int *msg_id)
{
    cJSON           *root       = NULL;
    cJSON           *payload    = NULL;
    cJSON           *params     = NULL;

    unsigned int    tmp_msg_id  = 0;
    char            *msg        = NULL;

    int             ret         = 0;

    if (LEDA_WS_CONNECTED != g_conn_state)
    {
        log_w(LOG_TAG, "the connection is disconnected\n");
        return LEDA_ERROR_CONNECTION;
    }

    if (NULL == pk || NULL == dn || NULL == method)
    {
        log_w(LOG_TAG, "pk: %s dn: %s method: %s has invlid value\n", pk, dn, method);
        return LE_ERROR_INVAILD_PARAM;
    }
    root = cJSON_CreateObject();
    if (NULL == root)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    payload = cJSON_CreateObject();
    if (NULL == payload)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        cJSON_Delete(root);
        return LE_ERROR_ALLOCATING_MEM;
    }
    tmp_msg_id = _ws_get_msg_id();

    cJSON_AddStringToObject(root, "version", PROTOCOL_VERSION);
    cJSON_AddNumberToObject(root, "messageId", tmp_msg_id);
    cJSON_AddStringToObject(root, "method", method);

    cJSON_AddItemToObject(root, "payload", payload);
    cJSON_AddStringToObject(payload, "productKey", pk);
    cJSON_AddStringToObject(payload, "deviceName", dn);

    /* 设备属性或事件数据 */
    params = struct_data_to_json_data(data, data_cnt);
    if (!params)
    {
        cJSON_Delete(root);
        return LE_ERROR_INVAILD_PARAM;
    }

    if (event_name)
    {
        cJSON_AddStringToObject(payload, "identifier", event_name);
        cJSON_AddItemToObject(payload, "outputData", params);
    }
    else
    {
        cJSON_AddItemToObject(payload, "properties", params);
    }

//next_step:

    msg = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (NULL == msg)
    {
        log_w(LOG_TAG, "no memory can allocate\n");
        return LE_ERROR_ALLOCATING_MEM;
    }

    log_i(LOG_TAG, "send  msg: %s", msg);
    ret = web_socket_send(g_fd, (unsigned char*)msg, strlen(msg), 1, WCT_TXTDATA);
    if( ret >= 0 ){
        ret = LE_SUCCESS;
    }
    cJSON_free(msg);
    if (ret != LE_SUCCESS)
    {
        log_w(LOG_TAG, "send timeout2\n");
        _ws_remove_reply(tmp_msg_id);
        return ret;
    }

    if (NULL != msg_id)
    {
        *msg_id = tmp_msg_id;
    }

    return ret;
}
/*
 * 上线设备, 设备只有上线后, 才能被 LinkEdge 识别.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口,成功返回LE_SUCCESS, 失败返回错误码.
 */
int leda_online(const char *product_key, const char *device_name){
   return leda_send_method(product_key, device_name, METHOD_ONLINE, NULL, NULL, 0);
}

/*
 * 下线设备, 假如设备工作在不正常的状态或设备退出前, 可以先下线设备, 这样LinkEdge就不会继续下发消息到设备侧.
 *
 * @product_key:          设备ProductKey.
 * @device_name:          设备DeviceName.
 *
 * 阻塞接口, 成功返回LE_SUCCESS,  失败返回错误码.
 *
 */
int leda_offline(const char *product_key, const char *device_name){
    return leda_send_method(product_key, device_name, METHOD_OFFLINE, NULL, NULL, 0);
}

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
int leda_report_event(const char *product_key, const char *device_name, const char *event_name, const leda_device_data_t data[], int data_count, unsigned int *msg_id){
    return leda_asyn_send_method(product_key, device_name, METHOD_REPORT_EVENT, event_name, data, data_count, msg_id);
}
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
int leda_report_properties(const char *product_key, const char *device_name, const leda_device_data_t properties[], int properties_count, unsigned int *msg_id){
    return leda_asyn_send_method(product_key, device_name, EMTHOD_REPORT_PROPERTY, NULL, properties, properties_count, msg_id);
}

int webinit(const leda_conn_info_t *info){
    int fd = -1;

    fd = web_socket_client_link_to_server(info->server_ip,info->server_port, "/null");
    if(fd < 0)
    {
        log_w(LOG_TAG,"client link to server failed !\r\n");
        return fd;
    }
    utc_sleepms(1000);
    return fd;
}

static void *webpthread(void *user_data){
    char buf[2048] = {0};
    int recvcount = 0;
    int* timeout =(int*)user_data;
    int timeoutMs = *timeout;
    while (1)
    {
        memset(buf, 0, sizeof(buf));
        int recvtmp = web_socket_recv(g_fd, (unsigned char*)buf, sizeof(buf));
        if(recvtmp > 0){
                 log_i(LOG_TAG,"recv msg: %s\r\n",buf);
                cb_ws_recv(buf, sizeof(buf),g_conn_cb.usr_data);
        }
        else if(recvtmp == WCT_PING){
                
        }
        else{
            recvcount++;
             log_w(LOG_TAG,"web_socket_recv fail: %d\r\n",recvcount);
        }
         utc_sleepms(10);
        if(recvcount >= (timeoutMs/10)){
            break;
        }
    }
    return NULL;
}
/*
 * 初始化.
 *
 * @info: 连接信息.
 * 阻塞接口, 成功返回LE_SUCCESS, 失败返回错误码.
 */
int leda_init(const leda_conn_info_t *info){

    int             ret         = 0;
    if (1 == g_has_init)
    {
        log_i(LOG_TAG, "leda has init\n");
        return LE_SUCCESS;
    }

    log_i(LOG_TAG, "leda init...\n");
  /* ws连接配置 */
    struct in_addr server_addr = {0};
    if ((NULL == info->server_ip) || (1 != inet_aton(info->server_ip, &server_addr)))
    {
        log_e(LOG_TAG, "server ip %s maybe NULL or invalid ip\n", info->server_ip);
        return LE_ERROR_INVAILD_PARAM;
    }

    if ((info->server_port) >= 65535)
    {
        log_e(LOG_TAG, "server port %u go beyond 65535\n", info->server_port);
        return LE_ERROR_INVAILD_PARAM;
    }

    if ((0 != info->use_tls) && (1 != info->use_tls))
    {
        log_e(LOG_TAG, "use tls value: %d is invalid, should be 0 or 1\n", info->use_tls);
        return LE_ERROR_INVAILD_PARAM;
    }

    /* 连接状态回调 */
    g_conn_cb.conn_state_change_cb      = info->ws_conn_cb.conn_state_change_cb;
    g_conn_cb.usr_data                  = info->ws_conn_cb.usr_data;

    /* 服务调用回调 */
    g_devs_cb.get_properties_cb         = info->conn_devices_cb.get_properties_cb;
    g_devs_cb.usr_data_get_property     = info->conn_devices_cb.usr_data_get_property;

    g_devs_cb.set_properties_cb         = info->conn_devices_cb.set_properties_cb;
    g_devs_cb.usr_data_set_property     = info->conn_devices_cb.usr_data_set_property;

    g_devs_cb.call_service_cb           = info->conn_devices_cb.call_service_cb;
    g_devs_cb.usr_data_call_service     = info->conn_devices_cb.usr_data_call_service;
    g_devs_cb.service_output_max_count  = info->conn_devices_cb.service_output_max_count;

    g_devs_cb.report_reply_cb           = info->conn_devices_cb.report_reply_cb;
    g_devs_cb.usr_data_report_reply     = info->conn_devices_cb.usr_data_report_reply;

    //ret = wsc_init(&g_param_conn, &param_cbs);
    g_fd = webinit(info);
    if (g_fd < 0)
    {
        log_e(LOG_TAG, "webinit error\n");
        return LE_FAIL;
    }
    //链接成功
    cb_ws_estab(g_conn_cb.usr_data);

    // hal_os_thread_param_t thread_parms = {0};
    // thread_parms.stack_size = 6144;
    // thread_parms.name = "websocket"; 
    // ret = HAL_ThreadCreate(&g_pthreadhandle,webpthread,NULL, &thread_parms,NULL);
    int s = info->timeout;
     utc_thread_create(&g_pthreadhandle,webpthread,&s);
    return ret;
}

/*
 * 退出.
 *
 * 退出前, 释放资源.
 *
 * 阻塞接口.
 */
void leda_exit(void){

    utc_thread_delete(g_pthreadhandle);
    //未连接
    close(g_fd);
   
    cb_ws_close(g_conn_cb.usr_data);

    g_has_init      = 0;
    g_conn_state    = -1;
    g_msg_id        = 0;

    log_w(LOG_TAG, "leda exit...\n");

    return;
}
