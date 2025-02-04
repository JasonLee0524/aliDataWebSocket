#include "utWebEx.h"
extern common_func g_globewebModule;
//================================================== 加密方法 sha1哈希 ==================================================
 
typedef struct SHA1Context{  
    unsigned Message_Digest[5];        
    unsigned Length_Low;               
    unsigned Length_High;              
    unsigned char Message_Block[64];   
    int Message_Block_Index;           
    int Computed;                      
    int Corrupted;                     
} SHA1Context;  
 
#define sha1_circular_shift(bits,word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32-(bits))))  
 
void sha1_process_message_block(SHA1Context *context)
{  
    const unsigned K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };  
    int         t;                  
    unsigned    temp;               
    unsigned    W[80];              
    unsigned    A, B, C, D, E;      
 
    for(t = 0; t < 16; t++) 
    {  
        W[t] = ((unsigned) context->Message_Block[t * 4]) << 24;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 1]) << 16;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 2]) << 8;  
        W[t] |= ((unsigned) context->Message_Block[t * 4 + 3]);  
    }  
 
    for(t = 16; t < 80; t++)  
        W[t] = sha1_circular_shift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);  
 
    A = context->Message_Digest[0];  
    B = context->Message_Digest[1];  
    C = context->Message_Digest[2];  
    D = context->Message_Digest[3];  
    E = context->Message_Digest[4];  
 
    for(t = 0; t < 20; t++) 
    {  
        temp =  sha1_circular_shift(5,A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = sha1_circular_shift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 20; t < 40; t++) 
    {  
        temp = sha1_circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = sha1_circular_shift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 40; t < 60; t++) 
    {  
        temp = sha1_circular_shift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = sha1_circular_shift(30,B);  
        B = A;  
        A = temp;  
    }  
    for(t = 60; t < 80; t++) 
    {  
        temp = sha1_circular_shift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];  
        temp &= 0xFFFFFFFF;  
        E = D;  
        D = C;  
        C = sha1_circular_shift(30,B);  
        B = A;  
        A = temp;  
    }  
    context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;  
    context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;  
    context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;  
    context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;  
    context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;  
    context->Message_Block_Index = 0;  
} 
 
void sha1_reset(SHA1Context *context)
{
    context->Length_Low             = 0;  
    context->Length_High            = 0;  
    context->Message_Block_Index    = 0;  
 
    context->Message_Digest[0]      = 0x67452301;  
    context->Message_Digest[1]      = 0xEFCDAB89;  
    context->Message_Digest[2]      = 0x98BADCFE;  
    context->Message_Digest[3]      = 0x10325476;  
    context->Message_Digest[4]      = 0xC3D2E1F0;  
 
    context->Computed   = 0;  
    context->Corrupted  = 0;  
}  
 
void sha1_pad_message(SHA1Context *context)
{  
    if (context->Message_Block_Index > 55) 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 64)  context->Message_Block[context->Message_Block_Index++] = 0;  
        sha1_process_message_block(context);  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    } 
    else 
    {  
        context->Message_Block[context->Message_Block_Index++] = 0x80;  
        while(context->Message_Block_Index < 56) context->Message_Block[context->Message_Block_Index++] = 0;  
    }  
    context->Message_Block[56] = (context->Length_High >> 24 ) & 0xFF;  
    context->Message_Block[57] = (context->Length_High >> 16 ) & 0xFF;  
    context->Message_Block[58] = (context->Length_High >> 8 ) & 0xFF;  
    context->Message_Block[59] = (context->Length_High) & 0xFF;  
    context->Message_Block[60] = (context->Length_Low >> 24 ) & 0xFF;  
    context->Message_Block[61] = (context->Length_Low >> 16 ) & 0xFF;  
    context->Message_Block[62] = (context->Length_Low >> 8 ) & 0xFF;  
    context->Message_Block[63] = (context->Length_Low) & 0xFF;  
 
    sha1_process_message_block(context);  
} 
 
int sha1_result(SHA1Context *context)
{
    if (context->Corrupted) 
    {  
        return 0;  
    }  
    if (!context->Computed) 
    {  
        sha1_pad_message(context);  
        context->Computed = 1;  
    }  
    return 1;  
}  
 
 
void sha1_input(SHA1Context *context,const char *message_array,unsigned length){  
    if (!length) 
        return;  
 
    if (context->Computed || context->Corrupted)
    {  
        context->Corrupted = 1;  
        return;  
    }  
 
    while(length-- && !context->Corrupted)
    {  
        context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);  
 
        context->Length_Low += 8;  
 
        context->Length_Low &= 0xFFFFFFFF;  
        if (context->Length_Low == 0)
        {  
            context->Length_High++;  
            context->Length_High &= 0xFFFFFFFF;  
            if (context->Length_High == 0) context->Corrupted = 1;  
        }  
 
        if (context->Message_Block_Index == 64)
        {  
            sha1_process_message_block(context);  
        }  
        message_array++;  
    }  
}

char * sha1_hash(const char *source){   // Main  
    SHA1Context sha;  
    char *buf;//[128];  
 
    sha1_reset(&sha);  
    sha1_input(&sha, source, strlen(source));  
 
    if (!sha1_result(&sha))
    {  
        printf("SHA1 ERROR: Could not compute message digest");  
        return NULL;  
    } 
    else 
    {  
        buf = (char *)g_globewebModule.utc_malloc(128);  
        memset(buf, 0, 128);  
        sprintf(buf, "%08X%08X%08X%08X%08X", sha.Message_Digest[0],sha.Message_Digest[1],  
        sha.Message_Digest[2],sha.Message_Digest[3],sha.Message_Digest[4]);  
        //lr_save_string(buf, lrvar);  
 
        //return strlen(buf);  
        return buf;  
    }  
}  
 
int tolower(int c)   
{   
    if (c >= 'A' && c <= 'Z')   
    {   
        return c + 'a' - 'A';   
    }   
    else   
    {   
        return c;   
    }   
}
 
int htoi(const char s[], int start, int len)   
{   
    int i, j;   
    int n = 0;   
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X')) //判断是否有前导0x或者0X  
    {   
        i = 2;   
    }   
    else   
    {   
        i = 0;   
    }   
    i+=start;  
    j=0;  
    for (; (s[i] >= '0' && s[i] <= '9')   
       || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >='A' && s[i] <= 'F');++i)   
    {     
        if(j>=len)  
        {  
            break;  
        }  
        if (tolower(s[i]) > '9')   
        {   
            n = 16 * n + (10 + tolower(s[i]) - 'a');   
        }   
        else   
        {   
            n = 16 * n + (tolower(s[i]) - '0');   
        }   
        j++;  
    }   
    return n;   
}   
 
//================================================== 加密方法BASE64 ==================================================
 
//base64编/解码用的基础字符集
const char base64char[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 
/*******************************************************************************
 * 名称: base64_encode
 * 功能: ascii编码为base64格式
 * 形参: bindata : ascii字符串输入
 *            base64 : base64字符串输出
 *          binlength : bindata的长度
 * 返回: base64字符串长度
 * 说明: 无
 ******************************************************************************/
int ut_base64_encode( const unsigned char *bindata, char *base64, int binlength)
{
    int i, j;
    unsigned char current;
    for ( i = 0, j = 0 ; i < binlength ; i += 3 )
    {
        current = (bindata[i] >> 2) ;
        current &= (unsigned char)0x3F;
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i] << 4 ) ) & ( (unsigned char)0x30 ) ;
        if ( i + 1 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+1] >> 4) ) & ( (unsigned char) 0x0F );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)(bindata[i+1] << 2) ) & ( (unsigned char)0x3C ) ;
        if ( i + 2 >= binlength )
        {
            base64[j++] = base64char[(int)current];
            base64[j++] = '=';
            break;
        }
        current |= ( (unsigned char)(bindata[i+2] >> 6) ) & ( (unsigned char) 0x03 );
        base64[j++] = base64char[(int)current];
        current = ( (unsigned char)bindata[i+2] ) & ( (unsigned char)0x3F ) ;
        base64[j++] = base64char[(int)current];
    }
    base64[j] = '\0';
    return j;
}
/*******************************************************************************
 * 名称: base64_decode
 * 功能: base64格式解码为ascii
 * 形参: base64 : base64字符串输入
 *            bindata : ascii字符串输出
 * 返回: 解码出来的ascii字符串长度
 * 说明: 无
 ******************************************************************************/
int ut_base64_decode( const char *base64, unsigned char *bindata)
{
    int i, j;
    unsigned char k;
    unsigned char temp[4];
    for ( i = 0, j = 0; base64[i] != '\0' ; i += 4 )
    {
        memset( temp, 0xFF, sizeof(temp) );
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i] )
                temp[0]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+1] )
                temp[1]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+2] )
                temp[2]= k;
        }
        for ( k = 0 ; k < 64 ; k ++ )
        {
            if ( base64char[k] == base64[i+3] )
                temp[3]= k;
        }
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[0] << 2))&0xFC)) | \
                ((unsigned char)((unsigned char)(temp[1]>>4)&0x03));
        if ( base64[i+2] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[1] << 4))&0xF0)) | \
                ((unsigned char)((unsigned char)(temp[2]>>2)&0x0F));
        if ( base64[i+3] == '=' )
            break;
        bindata[j++] = ((unsigned char)(((unsigned char)(temp[2] << 6))&0xF0)) | \
                ((unsigned char)(temp[3]&0x3F));
    }
    return j;
}
 
/*******************************************************************************
 * 名称: web_socket_get_random_string
 * 功能: 生成随机字符串
 * 形参: *buf：随机字符串存储到
 *              len : 生成随机字符串长度
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void web_socket_get_random_string(unsigned char *buf, unsigned int len)
{
    unsigned int i;
    unsigned char temp;
    srand((int)time(0));
    for(i = 0; i < len; i++)
    {
       temp = (unsigned char)g_globewebModule.utc_random(256);
       // temp = (unsigned char)(rand()%256);
        if(temp == 0)   // 随机数不要0, 0 会干扰对字符串长度的判断
            temp = 128;
        buf[i] = temp;
    }
}
/*******************************************************************************
 * 名称: web_socket_build_shake_key
 * 功能: client端使用随机数构建握手用的key
 * 形参: *key：随机生成的握手key
 * 返回: key的长度
 * 说明: 无
 ******************************************************************************/
int web_socket_build_shake_key(unsigned char *key)
{
    unsigned char tempKey[WEBSOCKET_SHAKE_KEY_LEN] = {0};
    web_socket_get_random_string(tempKey, WEBSOCKET_SHAKE_KEY_LEN);
    return ut_base64_encode((const unsigned char *)tempKey, (char *)key, WEBSOCKET_SHAKE_KEY_LEN);
}
/*******************************************************************************
 * 名称: web_socket_build_respond_shake_key
 * 功能: server端在接收client端的key后,构建回应用的key
 * 形参: *acceptKey：来自客户端的key字符串
 *         acceptKeyLen : 长度
 *          *respondKey :  在 acceptKey 之后加上 GUID, 再sha1哈希, 再转成base64得到 respondKey
 * 返回: respondKey的长度(肯定比acceptKey要长)
 * 说明: 无
 ******************************************************************************/
int web_socket_build_respond_shake_key(unsigned char *acceptKey, unsigned int acceptKeyLen, unsigned char *respondKey)
{
    char *clientKey;  
    char *sha1DataTemp;  
    char *sha1Data;  
    int i, n;  
    const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  
    unsigned int GUIDLEN;
 
    if(acceptKey == NULL)  
        return 0;  
    GUIDLEN = sizeof(GUID);
    clientKey = (char *)calloc(1, sizeof(char)*(acceptKeyLen + GUIDLEN + 10));  
    memset(clientKey, 0, (acceptKeyLen + GUIDLEN + 10));
    //
    memcpy(clientKey, acceptKey, acceptKeyLen); 
    memcpy(&clientKey[acceptKeyLen], GUID, GUIDLEN);
    clientKey[acceptKeyLen + GUIDLEN] = '\0';
    //
    sha1DataTemp = sha1_hash(clientKey);  
    n = strlen(sha1DataTemp);  
    sha1Data = (char *)calloc(1, n / 2 + 1);  
    memset(sha1Data, 0, n / 2 + 1);  
   //
    for(i = 0; i < n; i += 2)  
        sha1Data[ i / 2 ] = htoi(sha1DataTemp, i, 2);      
    n = ut_base64_encode((const unsigned char *)sha1Data, (char *)respondKey, (n / 2));
    //
     g_globewebModule.utc_free(sha1DataTemp);
     g_globewebModule.utc_free(sha1Data);
     g_globewebModule.utc_free(clientKey);
    return n;
}
/*******************************************************************************
 * 名称: web_socket_match_shake_key
 * 功能: client端收到来自服务器回应的key后进行匹配,以验证握手成功
 * 形参: *myKey：client端请求握手时发给服务器的key
 *            myKeyLen : 长度
 *          *acceptKey : 服务器回应的key
 *           acceptKeyLen : 长度
 * 返回: 0 成功  -1 失败
 * 说明: 无
 ******************************************************************************/
int web_socket_match_shake_key(unsigned char *myKey, unsigned int myKeyLen, unsigned char *acceptKey, unsigned int acceptKeyLen)
{
    int retLen;
    unsigned char tempKey[256] = {0};

    retLen = web_socket_build_respond_shake_key(myKey, myKeyLen, tempKey);
    if(retLen != acceptKeyLen)
    {
        printf("web_socket_match_shake_key : len err\r\n%s\r\n%s\r\n%s\r\n", myKey, tempKey, acceptKey);
        return -1;
    }
    else if(strcmp((const char *)tempKey, (const char *)acceptKey) != 0)
    {
        printf("web_socket_match_shake_key : str err\r\n%s\r\n%s\r\n", tempKey, acceptKey);
        return -1;
    }
    return 0;
}
/*******************************************************************************
 * 名称: web_socket_build_http_head
 * 功能: 构建client端连接服务器时的http协议头, 注意websocket是GET形式的
 * 形参: *ip：要连接的服务器ip字符串
 *          port : 服务器端口
 *    *interfacePath : 要连接的端口地址
 *      *shakeKey : 握手key, 可以由任意的16位字符串打包成base64后得到
 *      *package : 存储最后打包好的内容
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void web_socket_build_http_head(char *ip, int port, char *interfacePath, unsigned char *shakeKey, char *package)
{
    const char httpDemo[] = "GET %s HTTP/1.1\r\n"
                                                "Connection: Upgrade\r\n"
                                                "Host: %s:%d\r\n"
                                                "Sec-WebSocket-Key: %s\r\n"
                                                "Sec-WebSocket-Version: 13\r\n"
                                                "Upgrade: websocket\r\n\r\n";
    sprintf(package, httpDemo, interfacePath, ip, port, shakeKey);
}
/*******************************************************************************
 * 名称: web_socket_build_http_respond
 * 功能: 构建server端回复client连接请求的http协议
 * 形参: *acceptKey：来自client的握手key
 *          acceptKeyLen : 长度
 *          *package : 存储
 * 返回: 无
 * 说明: 无
 ******************************************************************************/
void web_socket_build_http_respond(unsigned char *acceptKey, unsigned int acceptKeyLen, char *package)
{
    const char httpDemo[] = "HTTP/1.1 101 Switching Protocols\r\n"
                                                "Upgrade: websocket\r\n"
                                                "Server: Microsoft-HTTPAPI/2.0\r\n"
                                                "Connection: Upgrade\r\n"
                                                "Sec-WebSocket-Accept: %s\r\n"
                                                "%s\r\n\r\n";  // 时间打包待续        // 格式如 "Date: Tue, 20 Jun 2017 08:50:41 CST\r\n"
    time_t now;
    struct tm *tm_now;
    char timeStr[256] = {0};
    unsigned char respondShakeKey[256] = {0};
    // 构建回应的握手key
    web_socket_build_respond_shake_key(acceptKey, acceptKeyLen, respondShakeKey);   
    // 构建回应时间字符串
    time(&now);
    tm_now = localtime(&now);
    strftime(timeStr, sizeof(timeStr), "Date: %a, %d %b %Y %T %Z", tm_now);
    // 组成回复信息
    sprintf(package, httpDemo, respondShakeKey, timeStr);
}
/*******************************************************************************
 * 名称: web_socket_enpackage
 * 功能: websocket数据收发阶段的数据打包, 通常client发server的数据都要isMask(掩码)处理, 反之server到client却不用
 * 形参: *data：准备发出的数据
 *          dataLen : 长度
 *        *package : 打包后存储地址
 *        packageMaxLen : 存储地址可用长度
 *          isMask : 是否使用掩码     1要   0 不要
 *          type : 数据类型, 由打包后第一个字节决定, 这里默认是数据传输, 即0x81
 * 返回: 打包后的长度(会比原数据长2~16个字节不等)      <=0 打包失败 
 * 说明: 无
 ******************************************************************************/
int web_socket_enpackage(unsigned char *data, unsigned int dataLen, unsigned char *package, unsigned int packageMaxLen, char isMask, Websocket_CommunicationType type)
{
    unsigned char maskKey[4] = {0};    // 掩码
    unsigned char temp1, temp2;
    int count;
    unsigned int i, len = 0;
 
    if(packageMaxLen < 2)
        return -1;
 
    if(type == WCT_MINDATA)
        *package++ = 0x00;
    else if(type == WCT_TXTDATA)
        *package++ = 0x81;
    else if(type == WCT_BINDATA)
        *package++ = 0x82;
    else if(type == WCT_DISCONN)
        *package++ = 0x88;
    else if(type == WCT_PING)
        *package++ = 0x89;
    else if(type == WCT_PONG)
        *package++ = 0x8A;
    else
        return -1;
    //
    if(isMask)
        *package = 0x80;
    len += 1;
    //
    if(dataLen < 126)
    {
        *package++ |= (dataLen&0x7F);
        len += 1;
    }
    else if(dataLen < 65536)
    {
        if(packageMaxLen < 4)
            return -1;
        *package++ |= 0x7E;
        *package++ = (char)((dataLen >> 8) & 0xFF);
        *package++ = (unsigned char)((dataLen >> 0) & 0xFF);
        len += 3;
    }
    else if(dataLen < 0xFFFFFFFF)
    {
        if(packageMaxLen < 10)
            return -1;
        *package++ |= 0x7F;
        *package++ = 0; //(char)((dataLen >> 56) & 0xFF);   // 数据长度变量是 unsigned int dataLen, 暂时没有那么多数据
        *package++ = 0; //(char)((dataLen >> 48) & 0xFF);
        *package++ = 0; //(char)((dataLen >> 40) & 0xFF);
        *package++ = 0; //(char)((dataLen >> 32) & 0xFF);
        *package++ = (char)((dataLen >> 24) & 0xFF);        // 到这里就够传4GB数据了
        *package++ = (char)((dataLen >> 16) & 0xFF);
        *package++ = (char)((dataLen >> 8) & 0xFF);
        *package++ = (char)((dataLen >> 0) & 0xFF);
        len += 9;
    }
    //
    if(isMask)    // 数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    {
        if(packageMaxLen < len + dataLen + 4)
            return -1;
        web_socket_get_random_string(maskKey, sizeof(maskKey));    // 随机生成掩码
        *package++ = maskKey[0];
        *package++ = maskKey[1];
        *package++ = maskKey[2];
        *package++ = maskKey[3];
        len += 4;
        for(i = 0, count = 0; i < dataLen; i++)
        {
            temp1 = maskKey[count];
            temp2 = data[i];
            *package++ = (char)(((~temp1)&temp2) | (temp1&(~temp2)));  // 异或运算后得到数据
            count += 1;
            if(count >= sizeof(maskKey))    // maskKey[4]循环使用
                count = 0;
        }
        len += i;
        *package = '\0';
    }
    else    // 数据没使用掩码, 直接复制数据段
    {
        if(packageMaxLen < len + dataLen)
            return -1;
        memcpy(package, data, dataLen);
        package[dataLen] = '\0';
        len += dataLen;
    }
    //
    return len;
}
/*******************************************************************************
 * 名称: web_socket_depackage
 * 功能: websocket数据收发阶段的数据解包, 通常client发server的数据都要isMask(掩码)处理, 反之server到client却不用
 * 形参: *data：解包的数据
 *          dataLen : 长度
 *        *package : 解包后存储地址
 *        packageMaxLen : 存储地址可用长度
 *        *packageLen : 解包所得长度
 * 返回: 解包识别的数据类型 如 : txt数据, bin数据, ping, pong等
 * 说明: 无
 ******************************************************************************/
int web_socket_depackage(unsigned char *data, unsigned int dataLen, unsigned char *package, unsigned int packageMaxLen, unsigned int *packageLen)
{
    unsigned char maskKey[4] = {0};    // 掩码
    unsigned char temp1, temp2;
    char Mask = 0, type;
    int count, ret;
    unsigned int i, len = 0, dataStart = 2;
    if(dataLen < 2)
        return -1;
 
    type = data[0]&0x0F;
 
    if((data[0]&0x80) == 0x80)
    {
        if(type == 0x01) 
            ret = WCT_TXTDATA;
        else if(type == 0x02) 
            ret = WCT_BINDATA;
        else if(type == 0x08) 
            ret = WCT_DISCONN;
        else if(type == 0x09) 
            ret = WCT_PING;
        else if(type == 0x0A) 
            ret = WCT_PONG;
        else 
            return WCT_ERR;
    }
    else if(type == 0x00) 
        ret = WCT_MINDATA;
    else
        return WCT_ERR;
    //
    if((data[1] & 0x80) == 0x80)
    {
        Mask = 1;
        count = 4;
    }
    else
    {
        Mask = 0;
        count = 0;
    }
    //
    len = data[1] & 0x7F;
    //
    if(len == 126)
    {
        if(dataLen < 4)
            return WCT_ERR;
        len = data[2];
        len = (len << 8) + data[3];
        if(dataLen < len + 4 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[4];
            maskKey[1] = data[5];
            maskKey[2] = data[6];
            maskKey[3] = data[7];
            dataStart = 8;
        }
        else
            dataStart = 4;
    }
    else if(len == 127)
    {
        if(dataLen < 10)
            return WCT_ERR;
        if(data[2] != 0 || data[3] != 0 || data[4] != 0 || data[5] != 0)    // 使用8个字节存储长度时, 前4位必须为0, 装不下那么多数据...
            return WCT_ERR;
        len = data[6];
        len = (len << 8) + data[7];
        len = (len << 8) + data[8];
        len = (len << 8) + data[9];
        if(dataLen < len + 10 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[10];
            maskKey[1] = data[11];
            maskKey[2] = data[12];
            maskKey[3] = data[13];
            dataStart = 14;
        }
        else
            dataStart = 10;
    }
    else
    {
        if(dataLen < len + 2 + count)
            return WCT_ERR;
        if(Mask)
        {
            maskKey[0] = data[2];
            maskKey[1] = data[3];
            maskKey[2] = data[4];
            maskKey[3] = data[5];
            dataStart = 6;
        }
        else
            dataStart = 2;
    }
    //
    if(dataLen < len + dataStart)
        return WCT_ERR;
    //
    if(packageMaxLen < len + 1)
        return WCT_ERR;
    //
    if(Mask)    // 解包数据使用掩码时, 使用异或解码, maskKey[4]依次和数据异或运算, 逻辑如下
    {
        //printf("depackage : len/%d\r\n", len);
        for(i = 0, count = 0; i < len; i++)
        {
            temp1 = maskKey[count];
            temp2 = data[i + dataStart];
            *package++ =  (char)(((~temp1)&temp2) | (temp1&(~temp2)));  // 异或运算后得到数据
            count += 1;
            if(count >= sizeof(maskKey))    // maskKey[4]循环使用
                count = 0;
            //printf("%.2X|%.2X|%.2X, ", temp1, temp2, *(package-1));
        }
        *package = '\0';
    }
    else    // 解包数据没使用掩码, 直接复制数据段
    {
        memcpy(package, &data[dataStart], len);
        package[len] = '\0';
    }
    *packageLen = len;
    //
    return ret;
}

/*******************************************************************************
 * 名称: web_socket_client_link_to_server
 * 功能: 向websocket服务器发送http(携带握手key), 以和服务器构建连接, 非阻塞模式
 * 形参: *ip：服务器ip
 *          port : 服务器端口
 *       *interface_path : 接口地址
 * 返回: >0 返回连接句柄      <= 0 连接失败或超时, 所花费的时间 ms
 * 说明: 无
 ******************************************************************************/
int web_socket_client_link_to_server(char *ip, int port, char *interface_path)
{
    int ret,fd , timeOut;
    //int i;
    unsigned char loginBuf[512] = {0}, shakeKey[128] = {0};
 
    // zhd服务器端网络地址结构体   
    struct sockaddr_in report_addr;     
    memset(&report_addr,0,sizeof(report_addr));             // 数据初始化--清零     
    report_addr.sin_family = AF_INET;                           // 设置为IP通信     
    report_addr.sin_addr.s_addr = inet_addr(ip);            // 服务器IP地址     
    report_addr.sin_port = htons(port);                             // 服务器端口号     
 
    //create unix socket  
    if((fd =  socket(AF_INET,SOCK_STREAM, IPPROTO_IP)) < 0) 
    {  
        printf("webSocket_login : cannot create socket\r\n");  
        return -1;  
    }
    
     // 测试 -----  创建握手key 和 匹配返回key
    web_socket_build_shake_key(shakeKey); 
    web_socket_build_respond_shake_key(shakeKey, strlen((const char*)shakeKey), shakeKey);
    //非阻塞
//    ret = lwip_fcntl(fd , F_GETFL , 0);
//    lwip_fcntl(fd , F_SETFL , ret | O_NONBLOCK);
 
    //connect
    timeOut = 0;
    while(connect(fd , (struct sockaddr *)&report_addr,sizeof(struct sockaddr)) == -1)
    {
        if(++timeOut > REPORT_LOGIN_CONNECT_TIMEOUT)
        {
            printf("webSocket_login : %s:%d cannot connect !  %d\r\n" , ip, port, timeOut);  
            close(fd); 
            return -timeOut;  
        }
        delayms(1);  //1ms 
    }
 
    //  setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&keepIdle, sizeof(keepIdle));
    // setsockopt(fd, IPPROTO_TCP,TCP_KEEPINTVL, (void *)&keepInterval, sizeof(keepInterval));
    // setsockopt(fd,IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(keepCount));

    //发送http协议头
    memset(shakeKey, 0, sizeof(shakeKey));
    web_socket_build_shake_key(shakeKey);  // 创建握手key
 
    memset(loginBuf, 0, sizeof(loginBuf));  // 创建协议包
    web_socket_build_http_head(ip, port, interface_path, shakeKey, (char *)loginBuf);   
    // 发出协议包
    ret = send(fd , loginBuf , strlen((const char*)loginBuf) , 0);
    if(ret <0){
            printf("ret send = %d,fd = %d\r\n",ret,fd);
    }
    return fd;
}
/*******************************************************************************
 * 名称: web_socket_server_link_to_client
 * 功能: 服务器回复客户端的连接请求, 以建立websocket连接
 * 形参: fd：连接句柄
 *          *recvBuf : 接收到来自客户端的数据(内含http连接请求)
 *              bufLen : 
 * 返回: =0 建立websocket连接成功        <0 建立websocket连接失败
 * 说明: 无
 ******************************************************************************/
int web_socket_server_link_to_client(int fd, char *recvBuf, unsigned int bufLen)
{
    char *p;
    int ret;
    char recvShakeKey[512], respondPackage[1024];
 
    if((p = strstr(recvBuf, "Sec-WebSocket-Key: ")) == NULL)
        return -1;
    p += strlen("Sec-WebSocket-Key: ");
    //
    memset(recvShakeKey, 0, sizeof(recvShakeKey));
    sscanf(p, "%s", recvShakeKey);      // 取得握手key
    ret = strlen(recvShakeKey);
    if(ret < 1)
        return -1;
    //
    memset(respondPackage, 0, sizeof(respondPackage));
    web_socket_build_http_respond((unsigned char*)recvShakeKey, ret, respondPackage);
    //
    return send(fd, respondPackage, strlen(respondPackage), 0);
}
/*******************************************************************************
 * 名称: web_socket_send
 * 功能: websocket数据基本打包和发送
 * 形参: fd：连接句柄
 *          *data : 数据
 *          dataLen : 长度
 *          mod : 数据是否使用掩码, 客户端到服务器必须使用掩码模式
 *          type : 数据要要以什么识别头类型发送(txt, bin, ping, pong ...)
 * 返回: 调用send的返回
 * 说明: 无
 ******************************************************************************/
int web_socket_send(int fd, unsigned char *data, unsigned int dataLen, char mod, Websocket_CommunicationType type)
{
    unsigned char *webSocketPackage;
    unsigned int retLen, ret;
 
   // printf("web_socket_send : %d\r\n", dataLen);
    //---------- websocket数据打包 ----------
    webSocketPackage = (unsigned char *)calloc(1, sizeof(char)*(dataLen + 128));  memset(webSocketPackage, 0, (dataLen + 128));
    retLen = web_socket_enpackage(data, dataLen, webSocketPackage, (dataLen + 128), mod, type);
    
   // printf("web_socket_send : %d\r\n" , retLen);
   // for(i = 0; i < retLen; i ++)  printf("%.2X ", webSocketPackage[i]);
   // printf("\r\n");
    ret = send(fd, webSocketPackage, retLen, 0);
     g_globewebModule.utc_free(webSocketPackage);
    return ret;
}
/*******************************************************************************
 * 名称: web_socket_recv
 * 功能: websocket数据接收和基本解包
 * 形参: fd：连接句柄
 *          *data : 数据接收地址
 *          dataMaxLen : 接收区可用最大长度
 * 返回: <= 0 没有收到有效数据        > 0 成功接收并解包数据
 * 说明: 无
 ******************************************************************************/
int web_socket_recv(int fd, unsigned char *data, unsigned int dataMaxLen)
{
    unsigned char *webSocketPackage, *recvBuf;
    int ret, ret2 = 0;
    unsigned int retLen = 0;
    recvBuf =   (unsigned char *)g_globewebModule.utc_malloc(sizeof(char)*dataMaxLen);
     memset(recvBuf, 0, dataMaxLen);

    ret = recv(fd, recvBuf, dataMaxLen, 0);
    //ret = write(fd , recvBuf , dataMaxLen);
    if(ret > 0)
    {
        //------------------------------------------------------------------- 和客户端的连接操作
        if(strncmp((const char*)recvBuf, "GET", 3) == 0)
        {
            ret2 = web_socket_server_link_to_client(fd, (char*)recvBuf, ret);
             g_globewebModule.utc_free(recvBuf);
            if(ret2 < 0)
            {
                memset(data, 0, dataMaxLen);
                strcpy((char*)data, "connect false !\r\n");
                return strlen("connect false !\r\n");
            }
            memset(data, 0, dataMaxLen);
            strcpy((char*)data, "connect ...\r\n");
            return strlen("connect ...\r\n");
        }
 
        //------------------------------------------------------------------- 正常数据交换
        //---------- websocket数据打包 ----------
        webSocketPackage =  (unsigned char *)g_globewebModule.utc_malloc(sizeof(char)*(ret + 128));
        //(unsigned char *)calloc(1, sizeof(char)*(ret + 128));  
        memset(webSocketPackage, 0, (ret + 128));
        ret2 = web_socket_depackage(recvBuf, ret, webSocketPackage, (ret + 128), &retLen);
        if(ret2 == WCT_PING)      // 解析为ping包, 自动回pong
        {
            web_socket_send(fd, webSocketPackage, retLen, 1, WCT_PONG);
            // 显示数据
           // printf("web_socket_recv : PING %d\r\n%s\r\n" , retLen, webSocketPackage); 
             g_globewebModule.utc_free(recvBuf);
             g_globewebModule.utc_free(webSocketPackage);
            return WCT_PING;
        }
         if (ret2 == WCT_TXTDATA || ret2 == WCT_BINDATA || ret2 == WCT_MINDATA) // 解析为数据包
        {
            memcpy(data, webSocketPackage, retLen);     // 把解析得到的数据复制出去
            /*
            // 显示数据
            if(webSocketPackage[0] >= ' ' && webSocketPackage[0] <= '~')
            { 
                printf("web_socket_recv : New Package StrFile ret2:%d/retLen:%d\r\n%s\r\n" , ret2, retLen, webSocketPackage); 
            }
            else
            {
                printf("web_socket_recv : New Package BinFile ret2:%d/retLen:%d\r\n" , ret2, retLen); 
                for(i = 0; i < retLen; i++) printf("%.2X ", webSocketPackage[i]); printf("\r\n");
            }*/
             g_globewebModule.utc_free(recvBuf);
             g_globewebModule.utc_free(webSocketPackage);
            return retLen;
        }
        g_globewebModule.utc_free(recvBuf);
         g_globewebModule.utc_free(webSocketPackage);
        return -ret;
    }
    else
    {
        g_globewebModule.utc_free(recvBuf);
        return ret;
    }
}
 
void delayms(unsigned int ms)
{
    g_globewebModule.utc_sleepms(ms);
}