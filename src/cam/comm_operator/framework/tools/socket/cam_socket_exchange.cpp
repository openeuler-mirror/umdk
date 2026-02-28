/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: CAM socket exchange file
 * Author: zhao yanchao
 * Create: 2025-05-30
 * Note:
 * History: 2025-05-30 create cam_socket_exchange file
 */
#include "cam_socket_exchange.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <csignal>
#include <cerrno>
#include <cstring>
#include <regex>
#include <set>
#include <string>
#include <fstream>
#include <sstream>

#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cam_env.h>

using namespace std;
namespace Cam {
constexpr const char *LOCAL_DEFAULT_LISTEN_IP = "127.0.0.1";
constexpr uint16_t LOCAL_DEFAULT_LISTEN_PORT = 10067;
constexpr uint32_t MAX_LISTEN_BACK_LOG = 65535;
static const std::regex ipv4_regex(
    R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)",
    std::regex::optimize
);

bool Ipv4IsValid(const std::string& ip) {
    return std::regex_match(ip, ipv4_regex);
}

int ParseIpAndPort(const char *input, string &ip, uint16_t &port)
{
    if (input == nullptr) {
        return CAM_INVALID_VALUE;
    }
    string inputStr(input);
    size_t colonPos = inputStr.find(':');
    if (colonPos == string::npos) {
        CAM_LOG(ERROR) << "Input string does not contain a colon seperating IP and port.";
        return CAM_ERROR_INTERNAL;
    }

    std::string tempIp = inputStr.substr(0, colonPos);
    if (!Ipv4IsValid(tempIp)) {
        CAM_LOG(ERROR) << "Invalid Ipv4 format, please check.";
        return CAM_INVALID_VALUE;
    }
    ip = tempIp;
    std::string portStr = inputStr.substr(colonPos + 1);

    std::istringstream portStream(portStr);
    portStream >> port;
    if (portStream.fail() || portStream.bad()) {
        CAM_LOG(ERROR) << "Invalid port number.";
        return CAM_ERROR_INTERNAL;
    }
    return CAM_SUCCESS;
}

CamSocketExchange::~CamSocketExchange()
{
    Cleanup();
}

CamSocketExchange::CamSocketExchange(int rank, int rankSize, std::vector<int> &rankList, std::string serverIpPort)
    : rank_(rank), rankSize_(rankSize), rankList_(rankList), serverIpPort_(serverIpPort)
{}


/**
 * 读取当前节点的UUID
 * 如果是服务器节点，收集所有客户端节点的UUID，并计算唯一UUID的数量（即节点的数量）
 * 如果是客户端节点，将自己的UUID发送给服务器，并从服务器接收最终的节点数量
 */
int CamSocketExchange::GetNodeNum()
{
    // 初始化检查
    if (!isInit_ && Prepare() != CAM_SUCCESS) {
        return CAM_ERROR_INTERNAL;
    }
    isInit_ = true;

    // 读取当前节点的UUID
    const string filePath = "/proc/sys/kernel/random/boot_id";
    ifstream fileStream(filePath);
    stringstream buffer;
    if (fileStream) {
        buffer << fileStream.rdbuf();
        fileStream.close();
    }
    const std::string uuid = buffer.str();
    CAM_LOG(DEBUG) << "rank:" << rank_ <<" UUID" << uuid;

    set<string> uuidSet{};
    uuidSet.insert(uuid);
    int nodeNum = -1;

    if (IsServer()) {   // 服务器节点处理逻辑
        for (int i = 1; i < rankSize_; ++i) {
            std::vector<char> receivedUuid(uuid.size(), '\0');
            if (Recv(clientFds_[i], receivedUuid.data(), receivedUuid.size(), 0) <= 0) {
                CAM_LOG(ERROR) << "Server side recv rank " << i << " buffer failed";
                return CAM_ERROR_INTERNAL;
            }
            CAM_LOG(INFO) << "receivedUuid: " << std::string(receivedUuid.begin(), receivedUuid.end());
            uuidSet.insert(std::string(receivedUuid.begin(), receivedUuid.end()));
        }
        nodeNum = static_cast<int32_t>(uuidSet.size());
        for (int i = 1; i < rankSize_; ++i) {
            if (Send(clientFds_[i], &nodeNum, sizeof(int), 0) <= 0) {
                CAM_LOG(ERROR) << "Server side send rank " << i << " buffer failed";
                return CAM_ERROR_INTERNAL;
            }
        }
    } else {    // 客户端节点处理逻辑
        if (Send(fd_, uuid.data(), uuid.size(), 0) <= 0) {
            CAM_LOG(ERROR) << "Client side " << rank_ << " send buffer failed";
            return CAM_ERROR_INTERNAL;
        }
        if (Recv(fd_, &nodeNum, sizeof(int), 0) <= 0) {
            CAM_LOG(ERROR) << "Client side " << rank_ << " send buffer failed";
            return CAM_ERROR_INTERNAL;
        }
    }
    CAM_LOG(INFO) << "nodeNum: " << nodeNum;
    return nodeNum;
}

void CamSocketExchange::GetIpAndPort()
{
    int serverRank = !rankList_.empty() ? rankList_[0] : 0;
    bool isParseOk = false;
    if (!serverIpPort_.empty() && ParseIpAndPort(serverIpPort_.c_str(), ip_, port_) == CAM_SUCCESS) {
        isParseOk = true;
    } else if (Cam::GetEnv("CAM_COMM_ID") != nullptr &&
                ParseIpAndPort(Cam::GetEnv("CAM_COMM_ID"), ip_, port_) == CAM_SUCCESS) {
        isParseOk = true;
    }
    if (!isParseOk) {
        ip_ = LOCAL_DEFAULT_LISTEN_IP;
        port_ = LOCAL_DEFAULT_LISTEN_PORT;
    }
    port_ += serverRank;
    camCommId_.handle.addr.sin.sin_family = AF_INET;
    // only connect localhost for safety
    camCommId_.handle.addr.sin.sin_addr.s_addr = inet_addr(ip_.c_str());
    camCommId_.handle.addr.sin.sin_port = htons(port_);
    CAM_LOG(DEBUG) << "curRank: " << rank_ << " serverRank: " << serverRank << " ip: " << ip_ << " port: " << port_;
}

int CamSocketExchange::Prepare()
{
    if (camCommId_.handle.magic != CAM_MAGIC) {
        GetIpAndPort();
    }
    if (!IsServer()) {
        return Connect();
    }

    clientFds_.resize(rankSize_, -1);
    if (Listen() != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "Listen Failed!";
        return CAM_ERROR_INTERNAL;
    }

    if (Accept() != CAM_SUCCESS) {
        CAM_LOG(ERROR) << "Accept Failed!";
        return CAM_ERROR_INTERNAL;
    }

    return CAM_SUCCESS;
}

int CamSocketExchange::Listen()
{
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
        CAM_LOG(ERROR) << "Server side create socket failed";
        return CAM_ERROR_INTERNAL;
    }

    int reuse = 1;
    // 设置套接字的选型，SO_REUSEADDR选项允许在同一地址和端口上重新绑定套接字，即便该地址和端口已被占用
    if (setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0) {
        CAM_LOG(ERROR) << "Server side set reuseaddr failed";
        return CAM_ERROR_INTERNAL;
    }

    struct sockaddr *addrPtr = &camCommId_.handle.addr.sa;
    if (bind(fd_, addrPtr, sizeof(struct sockaddr)) < 0) {
        CAM_LOG(ERROR) << "Server side bind" << ntohs(camCommId_.handle.addr.sin.sin_port) << "failed";
        return CAM_ERROR_INTERNAL;        
    }

    /**
     * kernel would silently truncate backlog to the value defined in
     * /proc/sys/net/core/somaxconn if it is less than 65535
     */
    if (listen(fd_, MAX_LISTEN_BACK_LOG) < 0) {
        CAM_LOG(ERROR) << "Server side listen" << ntohs(camCommId_.handle.addr.sin.sin_port) << "failed";
        return CAM_ERROR_INTERNAL;        
    }
    CAM_LOG(INFO) << "The server is listening! ip: " << inet_ntoa(camCommId_.handle.addr.sin.sin_addr)
                  << " port: " << ntohs(camCommId_.handle.addr.sin.sin_port);

    return CAM_SUCCESS;
}

int CamSocketExchange::AcceptConnection(int fd, sockaddr_in &clientAddr, socklen_t *sinSize) const
{
    int clientFd;
    CamSocketAddress clientAddrPtr;
    clientAddrPtr.sin = clientAddr;

    do {
        clientFd = accept(fd, &clientAddrPtr.sa, sinSize);
        if (clientFd < 0) {
            if (!CheckErrno(errno)) {
                CAM_LOG(ERROR) << "Server side accept failed" << strerror(errno);
                return -1;
            }
            CAM_LOG(DEBUG) << "accept failed: " << strerror(errno);
            continue;
        }
        break;
    } while (true);

    return clientFd;
}

int CamSocketExchange::Accept()
{
    struct sockaddr_in clientAddr;
    socklen_t sinSize = sizeof(struct sockaddr_in);

    for (int i = 1; i < rankSize_; ++i) {
        int fd = AcceptConnection(fd_, clientAddr, &sinSize);
        if (fd < 0) {
            CAM_LOG(ERROR) << "AcceptConnection failed";
            return CAM_ERROR_INTERNAL;
        }

        int rank = 0;
        if (Recv(fd, &rank, sizeof(rank), 0) <= 0) {
            CAM_LOG(ERROR) << "Server side recv rank id failed";
            return CAM_ERROR_INTERNAL;
        }

        if (rank >= rankSize_ || rank <= 0 || clientFds_[rank] >= 0) {
            CAM_LOG(ERROR) << "Server side recv invalid rank id" << rank;
            return CAM_ERROR_INTERNAL;
        }

        CAM_LOG(DEBUG) << "Server side recv rank id" << rank;
        clientFds_[rank] = fd;
    }

    return CAM_SUCCESS;
}

void CamSocketExchange::Close(int &fd) const
{
    if (fd == -1) {
        return;
    }

    if (close(fd) < 0) {
        CAM_LOG(WARN) << "failed to close fd:" << fd;
        return;
    }

    fd = -1;
}

int CamSocketExchange::Connect()
{
    CAM_LOG(DEBUG) << "Client side " << rank_ << " begin to connect";

    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
        CAM_LOG(ERROR) << "Client side " << rank_ << " create socket failed";
        return CAM_ERROR_INTERNAL;
    }

    int sleepTimeS = 1;
    int maxRetryCount = 180;
    int retryCount = 0;
    bool success = false;
    struct sockaddr *addrPtr = &camCommId_.handle.addr.sa;
    while (retryCount < maxRetryCount) {
        if (connect(fd_, addrPtr, sizeof(struct sockaddr)) < 0) {
            if (errno == ECONNREFUSED) {
                CAM_LOG(DEBUG) << "Client side " << rank_ << " try connect " << (retryCount + 1) << " times refused";
                retryCount++;
                sleep(sleepTimeS);
                continue;
            }
            if (errno != EINTR) {
                CAM_LOG(ERROR) << "Client side " << rank_ << " connect failed: " << strerror(errno);
                break;
            }
            CAM_LOG(DEBUG) << "Client side " << rank_ << " try connect failed: " << strerror(errno);
            continue;
        }
        success = true;
        break;
    }

    if (!success) {
        CAM_LOG(ERROR) << "Client side " << rank_ << " connect failed";
        return CAM_ERROR_INTERNAL;
    }

    if (Send(fd_, &rank_, sizeof(rank_), 0) <= 0) {
        CAM_LOG(ERROR) << "Client side " << rank_ << " send rank failed";
        return CAM_ERROR_INTERNAL;
    }

    return CAM_SUCCESS;
}

bool CamSocketExchange::IsServer() const
{
    return rank_ == 0;
}

void CamSocketExchange::Cleanup()
{
    if (fd_ >= 0) {
        Close(fd_);
    }

    if (clientFds_.empty()) {
        return;
    }

    for (int i = 1; i < rankSize_; ++i) {
        if (clientFds_[i] >= 0) {
            Close(clientFds_[i]);
        }
    }
}

}   //namespace Cam