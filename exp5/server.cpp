#include "basic.h"
#include <iostream>
#include <winsock2.h>
#include <cstring>

using namespace std;

const int PORT = 8888;
const string USER_FILE = USER_PATH;
const string ADMIN_FILE = ADMIN_PATH;
const string LICENSE_FILE = LICENSE_PATH;
SOCKET clientSocket,serverSocket;

// 用户信息结构体
struct UserInfo {
    string name;
    string password;
    string licenseInfo;
};

// 管理员信息结构体
struct AdminInfo {
    string name;
    string password;
    int licenseCount;
    std::vector<string> licenses;
};

struct LicenseInfo {
    string lId;
    int capacity;
    int used;
    std::vector<string> users;
};

map<string, UserInfo> users;   // 存储普通用户信息的映射
map<string, AdminInfo> admins; // 存储管理员信息的映射
map<string, LicenseInfo> useL;

// 初始化服务器
bool initializeServer(int port) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup failed" << endl;
        return false;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Socket creation failed" << endl;
        WSACleanup();
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    if (bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Bind failed" << endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Listen failed" << endl;
        closesocket(serverSocket);
        WSACleanup();
        return false;
    }

    return true;
}

// 加载用户信息
void loadUserInfoFromFile() {
    ifstream userFile(USER_FILE);
    if (userFile.is_open()) {
        users.clear(); // 清空当前用户信息
 
        string line;
        while (getline(userFile, line)) {
            stringstream ss(line);
            string uname, pwd, linfo;
            getline(ss, uname, ' ');
            getline(ss, pwd, ' ');
            getline(ss, linfo);

            UserInfo info = {uname, pwd, linfo};
            users[uname] = info; // 使用用户名作为键存储用户信息
        }
    
        userFile.close();
    } else {
        cerr << "Failed to open user file" << endl;
        std::ofstream outFile(USER_FILE);

        // 检查文件是否成功打开
        if (outFile.is_open()) {
            std::cout << "File created successfully: " << USER_FILE << std::endl;
            //outFile<<"username password license"<<endl;
            // 关闭文件流
            outFile.close();
        } else {
            std::cerr << "Failed to create file: " << USER_FILE << std::endl;
        }
    }
}
// 加载管理员信息
void loadAdminInfoFromFile() {
    ifstream adminFile(ADMIN_FILE);
    if (adminFile.is_open()) {
        admins.clear(); // 清空当前管理员信息

        string line;
        while (getline(adminFile, line)) {
            stringstream ss(line);
            string uname, pwd;
            int count;
            ss >> uname >> pwd >> count;

            vector<string> licenses;
            string license;
            while (ss >> license) {
                licenses.push_back(license);
            }

            AdminInfo info = {uname, pwd, count, licenses};
            admins[uname] = info; // 使用用户名作为键存储管理员信息
        }

        adminFile.close();
    } else {
        cerr << "Failed to open admin file" << endl;
        std::ofstream outFile(ADMIN_FILE);

    // 检查文件是否成功打开
    if (outFile.is_open()) {
        std::cout << "File created successfully: " << ADMIN_FILE << std::endl;
        //outFile<<"adminname password licenseCount licenseList"<<endl;
        // 关闭文件流
        outFile.close();
    } else {
        std::cerr << "Failed to create file: " << ADMIN_FILE << std::endl;
    }
    }
}
// 加载许可证的使用情况
void loadLicenseInfo() {
    ifstream licenseFile(LICENSE_PATH);
    if (licenseFile.is_open()) {
        useL.clear(); // 清空当前用户信息
        string line;
        while (getline(licenseFile, line)) {
            stringstream ss(line);
            string lId,tmp;
            int capacity,use;
            ss>>lId>>capacity>>use;
            vector<string> users;
            for (int i = 0; i < use; i++)
            {
                ss>>tmp;
                users.push_back(tmp);
            }
            
            struct LicenseInfo license = {lId,capacity,use,users};
            useL[lId] = license;
        }
    
        licenseFile.close();
    } else {
        cerr << "Failed to open user file" << endl;
        std::ofstream outFile(LICENSE_FILE);

        // 检查文件是否成功打开
        if (outFile.is_open()) {
            std::cout << "File created successfully: " << LICENSE_FILE << std::endl;
            //outFile<<"username password license"<<endl;
            // 关闭文件流
            outFile.close();
        } else {
            std::cerr << "Failed to create file: " << USER_FILE << std::endl;
        }
    }
}
// 保存用户信息到文件
void saveUserInfoToFile() {
    ofstream userFile(USER_FILE);
    if (userFile.is_open()) {
        for (const auto& pair : users) {
            const UserInfo& info = pair.second;
            userFile << info.name << " " << info.password << " " << info.licenseInfo << endl;
        }

        userFile.close();
    } else {
        cerr << "Failed to open user file for writing" << endl;
    }
}
// 保存管理员信息到文件
void saveAdminInfoToFile() {
    ofstream adminFile(ADMIN_FILE);
    if (adminFile.is_open()) {
        for (const auto& pair : admins) {
            const AdminInfo& info = pair.second;
            adminFile << info.name << " " << info.password << " " << info.licenseCount;
            for (const auto& license : info.licenses) {
                adminFile << " " << license;
            }
            adminFile << endl;
        }

        adminFile.close();
    } else {
        cerr << "Failed to open admin file for writing" << endl;
    }
}
// 保存许可证使用情况
void saveLicenseINfoTofile() {
    ofstream licenseFile(LICENSE_FILE);
    if (licenseFile.is_open()) {
        for (const auto& pair : useL) {
            licenseFile << pair.second.lId << " " << pair.second.capacity<<' '<<pair.second.used;
            for (int i = 0; i < pair.second.used; i++)
            {
                licenseFile<<' '<<pair.second.users[i];
            }
            licenseFile<<endl;
        }

        licenseFile.close();
    } else {
        cerr << "Failed to open license file for writing" << endl;
    }
}

// 账号是否存在
void accountExist(stringstream &ss)
{
    string name;
    getline(ss,name,' ');

    if(users.find(name)!=users.end())
    {
        const char* response = IS_A_USER;
        send(clientSocket,response,strlen(response),0);
    }
    else if(admins.find(name)!=admins.end())
    {
        const char* response = IS_A_ADMIN;
        send(clientSocket,response,strlen(response),0);
    }
    else
    {
        const char* response = ACCOUNT_NOT_EXIST;
        send(clientSocket,response,strlen(response),0);
    }
}
// 用户登陆
bool loginUser(stringstream &ss)
{
    string name,password;
    getline(ss,name,' ');
    getline(ss,password,' ');
    if(users[name].password == password) 
    {
        const char *response = LOGIN_SUCCESS;
        send(clientSocket, response, strlen(response), 0);
        return true;
    }
    else
    {
        const char *response =PASSWORD_INCORRECT;
        send(clientSocket, response, strlen(response), 0);
        return false;
    }
}
// 管理员登陆
bool loginAdmin(stringstream &ss)
{
    string name,password;
    getline(ss,name,' ');
    getline(ss,password,' ');
    if(admins[name].password == password) 
    {
        const char *response = LOGIN_SUCCESS;
        send(clientSocket, response, strlen(response), 0);
        return true;
    }
    else
    {
        const char *response =PASSWORD_INCORRECT;
        send(clientSocket, response, strlen(response), 0);
        return false;
    }
}
// 注册账户
bool registerAccount(stringstream &ss)
{
    string name,password,type;
    getline(ss,name,' ');
    getline(ss,password,' ');
    getline(ss,type,' ');

    if(type == "user")
    {
        if(users.find(name)!=users.end())
        {
            const char* response = ACCOUNT_ALREADY_EXIST;
            send(clientSocket,response,strlen(response),0);
            return false;
        }
        else
        {
            UserInfo newUser;
            newUser.name = name;
            newUser.password = password;
            newUser.licenseInfo = "null";
            users[name] = newUser;
            saveUserInfoToFile();

            const char* response = REGISTER_SUCCESS;
            send(clientSocket,response,strlen(response),0);
            return true;
        }
    }
    else if(type == "admin")
    {
        if(admins.find(name)!=admins.end())
        {
            const char* response = ACCOUNT_ALREADY_EXIST;
            send(clientSocket,response,strlen(response),0);
            return false;
        }
        else
        {
            AdminInfo newadmin;
            newadmin.name = name;
            newadmin.password = password;
            newadmin.licenseCount = 0;
            admins[name] = newadmin;
            saveAdminInfoToFile();

            const char* response = REGISTER_SUCCESS;
            send(clientSocket,response,strlen(response),0);

            return true;
        }
    }
    else return false;
}
// 购买许可证
bool buyLicense(stringstream &ss) {
    string name,password,type;
    getline(ss,name,' ');
    getline(ss,password,' ');
    getline(ss,type,' ');

    string id;
    srand(time(NULL));
    for (int i = 0; i < 10;i++)
    {
        id.push_back(rand()%10+'0');
    }
    cout<<"The license is:"<<id<<endl;
    int capacity = stoi(type);

    const char *response = id.c_str();
    send(clientSocket, response, strlen(response), 0);

    admins[name].licenseCount++;
    admins[name].licenses.push_back(id);
    struct LicenseInfo license = {id,capacity,0};
    useL[id] = license;
    saveLicenseINfoTofile();
    saveAdminInfoToFile();

    return true;

}
// 检查用户是否有许可证
bool checkLicense(stringstream &ss) {
    string response;
    string name,pass;
    getline(ss,name,' ');
    getline(ss,pass,' ');
    if(users[name].licenseInfo=="null") {
        response = NO_LICENSE;
        send(clientSocket, response.c_str(), response.size(), 0);
        return false;
    }
    else {
        response = HAVE_LICENSE;
        send(clientSocket, response.c_str(), response.size(), 0);
        return true;
    }
    
    
}
// 使用许可证
bool useLicense(stringstream &ss) {
    string name,license;
    getline(ss,name,' ');
    getline(ss,license,' ');

    string response;
    // 不存在 或 已满
    if(useL.find(license)==useL.end()||useL[license].used == useL[license].capacity) {
        response = USE_FAILED;
        send(clientSocket, response.c_str(), response.size(), 0);
        return false;
    } else {
        useL[license].used++;
        useL[license].users.push_back(name);
        users[name].licenseInfo = license;

        response = USE_SUCCESS;
        send(clientSocket, response.c_str(), response.size(), 0);
        saveLicenseINfoTofile();
        saveUserInfoToFile();
        return false;
    }
}
// 处理客户端连接
void handleClientConnection() {
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &clientAddrLen);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Accept failed" << endl;
        return;
    }

    cout << "Client connected" << endl;

    // 持续接收客户端数据
    char buffer[1024];
    int valread;
    while (true) {
        cout<<"Infos(handleClientConnection)"<<endl;
        cout<<"users count:"<<users.size()<<endl;
        cout<<"name password license"<<endl;
        for(auto user: users)
        {
            cout<<user.second.name<<' '<<user.second.password<<' '<<user.second.licenseInfo<<endl;
        }
        cout<<"admins count:"<<admins.size()<<endl;
        cout<<"name password licenseCount license(s)"<<endl;
        for(auto admin: admins)
        {
            cout<<admin.second.name<<' '<<admin.second.password<<' '<<admin.second.licenseCount;
            for (int i = 0; i < admin.second.licenseCount; i++)
                cout<<" "<<admin.second.licenses[i];
            cout<<endl;
        }
        cout<<"license count:"<<useL.size()<<endl;
        cout<<"licenseID capacity usedCount username(s)"<<endl;
        for(auto item: useL)
        {
            cout<<item.second.lId<<' '<<item.second.capacity<<' '<<item.second.used;
            for (int i = 0; i < item.second.used; i++)
                cout<<" "<<item.second.users[i];
            cout<<endl;
        }
        cout<<endl;
        memset(buffer, 0, sizeof(buffer)); // 清空缓冲区
        valread = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (valread == SOCKET_ERROR) {
            cerr << "Receive failed" << endl;
            break;
        } else if (valread == 0) {
            // 客户端关闭连接
            cout << "Client disconnected" << endl;
            closesocket(clientSocket);
            return; // 返回等待下一个连接
        } else {
            cout << "Received message from client: " << buffer << endl;
            stringstream ss = stringstream(buffer);
            string infoType;
            getline(ss,infoType,' ');

            
            if(infoType==I_ACCOUNT_EXIST) accountExist(ss);
            else if(infoType==I_LOGIN_USER) loginUser(ss);
            else if(infoType==I_LOGIN_ADMIN) loginAdmin(ss);
            else if(infoType==I_REGISTER_ACCOUNT) registerAccount(ss);
            else if(infoType==I_BUY_LICENSE) buyLicense(ss);
            else if(infoType==I_CHECK_LICENSE) checkLicense(ss);
            else if(infoType==I_SEND_LICENSE) useLicense(ss);
    }
        }
}

int main() {
    loadUserInfoFromFile();
    loadAdminInfoFromFile();
    loadLicenseInfo();
    // 初始化服务器
    if (!initializeServer(PORT)) {
        cerr << "Failed to initialize server" << endl;
        return 1;
    }

    cout << "Server listening on port " << PORT << "..." << endl;

    // 处理客户端连接
    while (true) {
        handleClientConnection();
    }

    // 关闭连接
    closesocket(serverSocket);
    WSACleanup();

    return 0;
}
