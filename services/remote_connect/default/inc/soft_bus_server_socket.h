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

#ifndef IAM_SOFT_SERVER_SOCKET_H
#define IAM_SOFT_SERVER_SOCKET_H

#include "soft_bus_base_socket.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ServerSocket : public BaseSocket {
public:
    ServerSocket(const int32_t socketId);
    ~ServerSocket() override = default;

    ResultCode SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback) override;

    void OnBind(int32_t socketId, PeerSocketInfo info) override;
    void OnShutdown(int32_t socketId, ShutdownReason reason) override;
    void OnBytes(int32_t socketId, const void *data, uint32_t dataLen) override;
    void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) override;

    std::string GetConnectionName() override;
    std::string GetNetworkId() override;

private:
    void AddServerSocket(const int32_t socketId, const std::string &networkId);
    void DeleteServerSocket(const int32_t socketId);

    void AddClientConnection(const int32_t socketId, const std::string &connectionName);
    void DeleteClientConnection(const int32_t socketId);

    std::string GetNetworkIdBySocketId(int32_t socketId);
    std::string GetClientConnectionName(const int32_t socketId);
    int32_t GetSocketIdByClientConnectionName(const std::string &ConnectionName);

    std::recursive_mutex socketMutex_;
    /* <socketId, networkId> */
    std::map<int32_t, std::string> serverSocketBindMap_;

    std::recursive_mutex connectionMutex_;
    /* <socketId, connectionName> */
    std::map<int32_t, std::string> clientConnectionMap_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_SERVER_SOCKET_H
