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

#ifndef IAM_SOFT_CLIENT_SOCKET_H
#define IAM_SOFT_CLIENT_SOCKET_H

#include <optional>

#include "soft_bus_base_socket.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ClientSocket : public BaseSocket {
public:
    ClientSocket(const int32_t socketId);
    ~ClientSocket() override;

    ResultCode SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback) override;

    void OnBind(int32_t socketId, PeerSocketInfo info) override;
    void OnShutdown(int32_t socketId, ShutdownReason reason) override;
    void OnBytes(int32_t socketId, const void *data, uint32_t dataLen) override;
    void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) override;

    std::string GetConnectionName() override;
    std::string GetNetworkId() override;
    void SetConnectionName(const std::string &connectionName);
    void SetNetworkId(const std::string &networkId);

private:
    void RefreshKeepAliveTimer();
    void SendKeepAliveMessage();

    std::string connectionName_;
    std::string endPointName_;
    std::string networkId_;
    std::optional<uint32_t> keepAliveTimerId_ = std::nullopt;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_CLIENT_SOCKET_H
