#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <ctime>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

// 获取当前时间的字符串表示
string get_current_time() {
    time_t now = time(nullptr);
    tm* localTime = localtime(&now);
    char timeStr[80];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localTime);
    return string(timeStr);
}

// 处理客户端请求的函数
void handle_client(SOCKET clientSocket) {
    sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    getpeername(clientSocket, (sockaddr*)&clientAddr, &addrLen);

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), ip, INET_ADDRSTRLEN);

    char buf[2048];
    int len = recv(clientSocket, buf, sizeof(buf), 0);

    uint32_t target_ip = *(uint32_t*)(buf + 4);
    uint16_t target_port = ntohs(*(uint16_t*)(buf + 2));
    in_addr inaddr;
    inaddr.s_addr = target_ip;
    char* target_ip_str = inet_ntoa(inaddr);

    cout << get_current_time() << " 客户端接入并访问：" << target_ip_str << ":" << target_port << endl;

    int targetSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (targetSocket < 0) {
        return;
    }

    sockaddr_in targetAddr = {};
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(target_port);
    targetAddr.sin_addr.s_addr = inet_addr(target_ip_str);

    connect(targetSocket, (sockaddr*)&targetAddr, sizeof(targetAddr));

    char success_response[8] = { 0x00, 0x5A };
    send(clientSocket, success_response, sizeof(success_response), 0);

    fd_set readfds;
    vector<SOCKET> sockets = { clientSocket, targetSocket };
    char buffer[4096];
    int bytes_read, bytes_written;

    while (true) {
        FD_ZERO(&readfds);
        for (auto s : sockets) {
            FD_SET(s, &readfds);
        }

        if (select(0, &readfds, nullptr, nullptr, nullptr) == SOCKET_ERROR) {
            cerr << "select failed: " << WSAGetLastError() << endl;
            closesocket(clientSocket);
            closesocket(targetSocket);
            WSACleanup();
            exit(EXIT_FAILURE);
        }

        for (auto s : sockets) {
            if (FD_ISSET(s, &readfds)) {
                bytes_read = recv(s, buffer, sizeof(buffer), 0);
                if (bytes_read <= 0) {
                    closesocket(s);
                    sockets.erase(remove(sockets.begin(), sockets.end(), s), sockets.end());
                } else {
                    int target = (s == clientSocket) ? targetSocket : clientSocket;
                    bytes_written = send(target, buffer, bytes_read, 0);
                    if (bytes_written <= 0) {
                        cerr << "send failed: " << WSAGetLastError() << endl;
                        closesocket(clientSocket);
                        closesocket(targetSocket);
                        WSACleanup();
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }

        if (sockets.empty()) break; // 当所有sockets都关闭时，退出循环
    }

    closesocket(targetSocket);
    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket;
    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "初始化 Winsock 失败" << endl;
        return -1;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "创建套接字失败" << endl;
        WSACleanup();
        return -1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("192.168.10.1");
    serverAddr.sin_port = htons(1800);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "绑定套接字失败" << endl;
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }

    if (listen(serverSocket, 5) == SOCKET_ERROR) {
        cerr << "监听失败" << endl;
        closesocket(serverSocket);
        WSACleanup();
        return -1;
    }

    cout << "等待客户端连接..." << endl;

    while (true) {
        SOCKET clientSocket;
        sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "接受连接失败" << endl;
            continue;
        }
        thread(clientThreadOBJ, clientSocket).detach();
    }

    closesocket(serverSocket);
    WSACleanup();

    return 0;
}
