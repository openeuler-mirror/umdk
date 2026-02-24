#ifndef CAM_SOCKET_EXCHANGE_H
#define CAM_SOCKET_EXCHANGE_H

#include <vector>
#include <string>
#include <memory>
#include <securec.h>
#include <cstdint>
#include <cerrno>

#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "cam_log.h"

#include "cam_types.h"
#include "cam_api.h"

namespace Cam {
union CamSocketAddress {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

constexpr uint64_t CAM_MAGIC = 0xdddd0000dddd0000;
struct CamBootstrapHandle {
    uint64_t magic;
    union CamSocketAddress addr;
};
union CamBootstrap {
    CamBootstrapHandle handle;
};

int BootstrapGetRootInfo(CamBootstrapHandle *handle);

class CamSocketExchange {
public:
    CamSocketExchange(int rank, int rankSize, std::vector<int> &rankList, std::string serverIpPort);
    ~CamSocketExchange();

    template <typename T> int AllGather(const T *sendBuf, size_t sendCount, T *recvBuf)
    {
        if (!isInit_ && Prepare() != CAM_SUCCESS) {
            return CAM_ERROR_INTERNAL;
        }
        isInit_ = true;

        if (!IsServer()) {
            return ClientSendRecv(sendBuf, sendCount, recvBuf);
        } else {
            return ServerRecvSend(sendBuf, sendCount, recvBuf);
        }
    }
    int GetNodeNum();

private:
    void GetIpAndPort();
    int Prepare();
    int Listen();
    int Accept();
    void Close(int &fd) const;
    int Connect();
    int AcceptConnection(int fd, sockaddr_in &clientAddr, socklen_t *sinSize) const;
    void Cleanup();
    bool IsServer() const;
    static bool CheckErrno(int ioErrno)
    {
        return ((ioErrno == EAGAIN) || (ioErrno == EWOULDBLOCK) || (ioErrno == EINTR));
    }

    template <typename T> int Send(int fd, const T *sendBuf, size_t sendSize, int flag) const
    {
        do {
            auto ret = send(fd, sendBuf, sendSize, flag);
            if (ret < 0) {
                if (CheckErrno(errno)) {
                    CAM_LOG(ERROR) << "send failed: " << strerror(errno);
                    continue;
                }
                CAM_LOG(DEBUG) << "Send failed: " << strerror(errno);
            }
            return ret;
        } while (true);
    }

    template <typename T> int Recv(int fd, T *recvBuf, size_t recvSize, int flag) const
    {
        do {
            auto ret = recv(fd, recvBuf, recvSize, flag);
            if (ret < 0) {
                if (CheckErrno(errno)) {
                    CAM_LOG(ERROR) << "recv failed: " << strerror(errno);
                    continue;
                }
                CAM_LOG(DEBUG) << "recv failed: " << strerror(errno);
            }
            return ret;
        } while (true);
    }

    template <typename T> int ClientSendRecv(const T *sendBuf, size_t sendSize, T *recvBuf)
    {
        if (Send(fd_, sendBuf, sendSize * sizeof(T), 0) <= 0) {
            CAM_LOG(ERROR) << "Client side " << rank_ << " send buffer failed";
            return CAM_ERROR_INTERNAL;
        }

        if (Recv(fd_, recvBuf, sendSize * rankSize_ * sizeof(T), MSG_WAITALL) <= 0) {
            CAM_LOG(ERROR) << "Client side " << rank_ << " recv buffer failed ";
            return CAM_ERROR_INTERNAL;
        }
        return CAM_SUCCESS;
    }

    template <typename T> int ServerRecvSend(const T *sendBuf, size_t sendSize, T *recvBuf)
    {
        auto ret = memcpy_s(recvBuf, sendSize * sizeof (T), sendBuf, sendSize * sizeof (T));
        if (ret != EOK) {
            CAM_LOG(ERROR) << "Failed to copy sendBuf to recvBuf.";
            return CAM_ERROR_INTERNAL;
        }

        for (int i = 1; i < rankSize_; ++i) {
            if (Recv(clientFds_[i], recvBuf + i * sendSize, sendSize * sizeof(T), MSG_WAITALL) <= 0) {
                CAM_LOG(ERROR) << "Server side recv rank " << i << " buffer failed";
                return CAM_ERROR_INTERNAL;
            }
        }

        for (int i = 1; i < rankSize_; ++i) {
            if (Send(clientFds_[i], recvBuf, sendSize * rankSize_ * sizeof(T), 0) <= 0) {
                CAM_LOG(ERROR) << "Server side send rank " << i << " buffer failed";
                return CAM_ERROR_INTERNAL;
            }
        }

        return CAM_SUCCESS;
    }

    int rank_ = 0;
    int rankSize_ = 0;
    int fd_ = -1;
    std::vector<int> clientFds_ = {};
    bool isInit_ = false;
    std::vector<int> rankList_ = {};
    std::string ip_ = "";
    uint16_t port_ = 0;
    CamBootstrap camCommId_ = {};
    std::string serverIpPort_ = "";
};
}

#endif