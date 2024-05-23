#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <winsock2.h>
#include <ctime>

using namespace std;

#define IS_A_USER "user"
#define IS_A_ADMIN "admin"
#define ACCOUNT_NOT_EXIST "null"
#define ACCOUNT_ALREADY_EXIST "Account already exist"
#define REGISTER_SUCCESS "Registration successful"
#define PASSWORD_INCORRECT "Password incorrect"
#define LOGIN_SUCCESS "Log in successfully"
#define NO_LICENSE "You have no license now"
#define HAVE_LICENSE "You are using a license"
#define USE_SUCCESS "Use the license successfully"
#define USE_FAILED "License is not existed or full"

#define USER_PATH "resource/server_user.txt"
#define ADMIN_PATH "resource/server_admin.txt"
#define LICENSE_PATH "resource/server_license.txt"

// 统一客户端与进程间的指令代码
#define I_ACCOUNT_EXIST "000"
#define I_LOGIN_USER "001"
#define I_LOGIN_ADMIN "002"
#define I_REGISTER_ACCOUNT "003"
#define I_BUY_LICENSE "004"
#define I_CHECK_LICENSE "005"
#define I_SEND_LICENSE "006"

