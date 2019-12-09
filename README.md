# aliDataWebSocket
跨平台的websocket通信，支持阿里云的物模型数据格式的消息通讯

代码上传的os实现，是基于esp8266/32的平台进行开发和验证的，因为libwebsocket比较庞大，不适合嵌入式平台。
该套代码用户只需要修改os的实现即可，完成在不同平台的消息通讯，前提是平台支持网络协议栈：例如系统的socket或者LwIP协议栈的支持。
乐鑫的环境：https://github.com/espressif/esp-aliyun
阿里的接入数据格式：https://github.com/aliyun/linkedge-thing-access-websocket_client_sdk

