#include "basic.h"

string curAccountName;
string curAccountPass;
bool isAdmin;
bool isLogin;
bool firstLogin;
SOCKET clientSocket;
void reset()
{
    curAccountName = "";
    isAdmin = false;
    isLogin = false;
    firstLogin = false;
}
const int PORT = 8888;
const char *SERVER_IP = "127.0.0.1"; // 服务器 IP 地址，这里假设是本地地址

bool connectToServer() {
    WSADATA wsaData;
    struct sockaddr_in serverAddr;

    // 初始化 Winsock 库
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed" << endl;
        return false;
    }

    // 创建客户端 socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed" << endl;
        WSACleanup();
        return false;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    // 将 IP 地址转换为网络字节序
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    if (serverAddr.sin_addr.s_addr == INADDR_NONE) {
        cerr << "Invalid address" << endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    // 连接到服务器
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Connection failed" << endl;
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    cout << "Connected to server" << endl;
    return true;
}

// 登陆的多个流程
// 先向服务器发送用户名，检测是否存在以及类型，返回User Admin Null三种状态
// 分别登陆用户，登陆管理员，注册账号实现最终登陆操作
string accountExist(string &name)
{
    string request = string(I_ACCOUNT_EXIST) + ' ' + name;
    send(clientSocket,request.c_str(),request.length(),0);
    char buffer[1024] = {0};
    int valread;
    if ((valread = recv(clientSocket, buffer, 1024, 0)) < 0) {
        cerr << "Receive failed" << endl;
        return "Receive failed";
    }
    return buffer;
}
bool loginUser(string username)
{
    std::cout<<"This account is a user"<<endl;
    string password,request;
    int valread;
    char buffer[1024] = {0};
    do
    {
        if(buffer == PASSWORD_INCORRECT) std::cout<<"Password incorrect"<<endl;
        std::cout<<"Enter password(or 'exit' to quit):";
        std::cin>> password;
        if(password=="quit") return false;
        request = string(I_LOGIN_USER) +" "+username+' '+password;
        send(clientSocket,request.c_str(),request.length(),0);
        if((valread = recv(clientSocket,buffer,1024,0))<0)
        {
            cerr << "Receive failed" << endl;
            return false;
        }
        cout<<buffer<<endl;
    } while (buffer == PASSWORD_INCORRECT);
    return true;
}
bool loginAdmin(string adminName)
{
    std::cout<<"Is a admin"<<endl;
    string password,request;
    int valread;
    char buffer[1024] = {0};
    do
    {
        if(strcmp(buffer,PASSWORD_INCORRECT)==0) std::cout<<"Password incorrect"<<endl;
        std::cout<<"Enter password(or 'exit' to quit):";
        std::cin>> password;
        if(strcmp(password.c_str(),"exit")==0) return false;
        request = string(I_LOGIN_ADMIN)+" "+adminName+' '+password;
        send(clientSocket,request.c_str(),request.length(),0);
        if((valread = recv(clientSocket,buffer,1024,0))<0)
        {
            cerr << "Receive failed" << endl;
            return false;
        }
    } while (strcmp(buffer,PASSWORD_INCORRECT)==0);

    if(strcmp(LOGIN_SUCCESS,buffer)==0) {
        curAccountPass = password;
        return true;
    }else return false;
    
}
bool registerAccount(string name)
{
    string password;
    std::cout << "Enter password: ";
    std::cin >> password;

    string isAdminStr;
    bool isAdmin;
    std::cout << "Are you an administrator? (yes/no): ";
    std::cin >> isAdminStr;
    isAdmin = (isAdminStr == "yes");

    // 发送注册请求给服务器
    string registerRequest = string(I_REGISTER_ACCOUNT)+' '+name + " " + password + " " + (isAdmin ? "admin" : "user");
    send(clientSocket, registerRequest.c_str(), registerRequest.length(), 0);

    // 接收服务器的响应
    char buffer[1024] = {0};
    int valread;
    if ((valread = recv(clientSocket, buffer, 1024, 0)) < 0) {
        cerr << "Receive failed" << endl;
        return false;
    }

    string response(buffer);
    if (response == REGISTER_SUCCESS) {
        curAccountName = name;
        isAdmin = true;
        return true;
    } else {
        cerr << "Registration failed: " << response << endl;
        return false;
    }
}
bool login(string name)
{
    string type = accountExist(name);
    if(type=="user")
    {
        if(loginUser(name))
        {
            curAccountName = name;
            isAdmin = false;
            return true;
        }
        else return false;
    }
    else if(type=="admin")
    {
        if(loginAdmin(name))
        {
            curAccountName = name;
            isAdmin = true;
            return true;
        }
        else return false;
    }
    else
    {
        string registerChoice;
        std::cout << "Account not found. Would you like to register? (yes/no): ";
        std::cin>>registerChoice;
        if(registerChoice=="yes") registerAccount(name);
        else return false;
    }
    return false;
}

// 购买与使用许可证
bool buyLicense()
{
    string type;
    cout<<"Input count of license could capacity?(50/10/2):";
    cin>>type;
    if(type == "50"||type == "10"||type == "2") {
        string request = string(I_BUY_LICENSE)+' '+curAccountName+' '+curAccountPass+' '+type;
        send(clientSocket,request.c_str(),request.size(),0);
        int valread;
        char buffer[1024];
        if((valread = recv(clientSocket,buffer,1024,0))<0)
        {
            cerr << "Receive failed" << endl;
            return false;
        }
        cout <<"get license:"<<buffer<<endl;
        return true;
    }
    return false;
    
}
bool toUse() {
    string request = string(I_CHECK_LICENSE)+' '+curAccountName+' '+curAccountPass;
    char buffer[1024];
    int valread;
    send(clientSocket,request.c_str(),request.length(),0);
    if((valread = recv(clientSocket,buffer,1024,0))<0)
    {
        cerr << "Receive failed" << endl;
        return false;
    }

    string command;
    cout<<buffer<<endl;
    if(strcmp(buffer,NO_LICENSE) == 0) {
        cout<<"Enter a license to use the software:";
        cin>>command;
        int flag = 1;
        if(command.size()!=10) {
            cout<<"The length must be 10"<<endl;
            return false;
        }
        for (int i = 0; i < command.size(); i++)
        {
            if(command[i]<'0'||command[i]>'9') flag =0;
        }
        
        if(flag == 0) {
            cout<<"The license consist of numbers"<<endl;
            return false;
        }
        request = string(I_SEND_LICENSE)+' '+curAccountName + ' ' + command;
        send(clientSocket,request.c_str(),request.length(),0);
        if((valread = recv(clientSocket,buffer,1024,0))<0)
        {
            cerr << "Receive failed" << endl;
            return false;
        }
        cout<<buffer<<endl;
        if(buffer==USE_SUCCESS) return true;
        else return false;

    } else if(strcmp(buffer,HAVE_LICENSE) == 0) {
        cout<<"You have already use a license"<<endl;
        return true;
    }
    return false;
}
int main() {
    if (!connectToServer()) {
        return 1;
    }

    while (true) {
        reset();
        // 读取用户输入
        std::cout << "Enter accountname (or 'exit' to quit): ";
        string accountname;
        std::cin >> accountname;

        // 检查用户是否想退出
        if (accountname == "exit") {
            break;
        }

        // 检查消息是否为空
        if (accountname.empty()) {
            cout << "Cannot send empty message" << endl;
            continue;
        }

        if (login(accountname))
        {
            if(isAdmin)
            {
                string confirm;
                cout<<"Buy license?(yes/not):";
                cin>>confirm;
                if(confirm == "yes") {
                    if(buyLicense()) cout<<"Buy license successfully!"<<endl;        
                    else cout<<"Buy license failed"<<endl;            
                }   

            }
            else
            {
                toUse();
            }
        }

    }

    // 关闭连接
    closesocket(clientSocket);
    WSACleanup();

    return 0;
}
