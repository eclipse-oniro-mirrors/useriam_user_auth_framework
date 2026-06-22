/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef IAM_SOFT_BUS_MANAGER_H
#define IAM_SOFT_BUS_MANAGER_H

#include <cstdint>
#include <string>
#include <map>
#include <mutex>

#include "iam_check.h"
#include "iam_common_defines.h"
#include "soft_bus_client_socket.h"
#include "soft_bus_server_socket.h"
#include "system_ability_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
inline static const std::string USER_AUTH_PACKAGE_NAME = "ohos.useriam";
class SoftBusManager {
public:
    virtual ~SoftBusManager();
    static SoftBusManager &GetInstance();
    void Start();
    void Stop();

    ResultCode OpenConnection(const std::string &connectionName, const uint32_t tokenId, const std::string &networkId);
    ResultCode CloseConnection(const std::string &connectionName);

    ResultCode SendMessage(const std::string &connectionName,
        const std::string &srcEndPoint, const std::string &destEndPoint,
        const std::shared_ptr<Attributes> &attributes, MsgCallback &callback);

    std::shared_ptr<BaseSocket> FindClientSocket(const std::string &connectionName);
    std::shared_ptr<BaseSocket> GetServerSocket();
    std::shared_ptr<BaseSocket> FindSocketBySocketId(const int32_t socketId);

    void OnBind(int32_t socketId, PeerSocketInfo info);
    void OnShutdown(int32_t socketId, ShutdownReason reason);
    void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) {};
    void OnClientBytes(int32_t socketId, const void *data, uint32_t dataLen);
    void OnServerBytes(int32_t socketId, const void *data, uint32_t dataLen);
    void DoOpenConnection(const std::string &connectionName, const uint32_t tokenId,
        const std::string &networkId);
    ResultCode DoCloseConnection(const std::string &connectionName);

private:
    SoftBusManager();
    ResultCode RegistDeviceManagerListener();
    ResultCode UnRegistDeviceManagerListener();
    ResultCode RegistSoftBusListener();
    ResultCode UnRegistSoftBusListener();

    ResultCode DeviceInit();
    void DeviceUnInit();
    ResultCode DoServiceSocketInit();
    void ServiceSocketInit();
    void ServiceSocketUnInit();

    ResultCode ServiceSocketListen(const int32_t socketId);
    int32_t ClientSocketInit(const std::string &connectionName, const std::string &networkId);
    ResultCode ClientSocketBind(const int32_t socketId);
    bool CheckAndCopyStr(char *dest, uint32_t destLen, const std::string &src);
    void AddConnection(const std::string &connectionName, std::shared_ptr<BaseSocket> &socket);
    void DeleteConnection(const std::string &connectionName);
    void AddSocket(const int32_t socketId, std::shared_ptr<BaseSocket> &socket);
    void DeleteSocket(const int32_t socketId);
    void SetServerSocket(std::shared_ptr<BaseSocket> &socket);
    void ClearServerSocket();
    ResultCode DoOpenConnectionInner(const std::string &connectionName, const uint32_t tokenId,
        const std::string &networkId, RemoteConnectOpenTrace &trace);

    std::recursive_mutex mutex_;
    bool inited_ = false;

    std::recursive_mutex ServerSocketMutex_;
    std::shared_ptr<BaseSocket> serverSocket_ {nullptr};

    std::recursive_mutex socketMutex_;
    std::map<int32_t, std::shared_ptr<BaseSocket>> socketMap_;

    std::recursive_mutex connectionMutex_;
    /* <ConnectionName, std::shared_ptr<BaseSocket>> */
    std::map<std::string, std::shared_ptr<BaseSocket>> clientSocketMap_;

    std::recursive_mutex deviceManagerMutex_;
    sptr<SystemAbilityListener> deviceManagerServiceListener_ {nullptr};

    std::recursive_mutex softBusMutex_;
    sptr<SystemAbilityListener> softBusServiceListener_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_BUS_MANAGER_H