# DPDK-TCP-UDP_Protocol_Stack
Simple protocol stack based on dpdk（使用dpdk搭建协议栈）

为了对协议栈了解更深入一些，借助dpdk-19.11实现一个简易协议栈。

本项目要完成的工作如下：
1. dpdk相关配置
2. 实现协议栈，主要针对TCP与UDP，包含三次握手、四次挥手
3. 实现服务端socket系统调用api：socket、bind、listen、accept、recv、send、recvfrom、sendto、recv、send、close
4. 实现epoll多线程

## 使用
1. 环境：安装dpdp-19.11，多队列网卡
2. make clean;make
3. sh run.sh

## 注意
本项目目前正在逐步优化，欢迎同学们指出不足哈！
