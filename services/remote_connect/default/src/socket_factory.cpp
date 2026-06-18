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
#include "socket_factory.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "soft_bus_client_socket.h"
#include "soft_bus_server_socket.h"

#define LOG_FILE_ID LOG_FILE_SOCKET_FACTORY
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<BaseSocket> SocketFactory::CreateClientSocket(const int32_t socketId, const std::string &connectionName,
    const std::string &networkId)
{
    IAM_LOGI("start.");
    auto clientSocket = Common::MakeShared<ClientSocket>(socketId);
    if (clientSocket == nullptr) {
        return nullptr;
    }

    clientSocket->SetConnectionName(connectionName);
    clientSocket->SetNetworkId(networkId);
    return clientSocket;
}

std::shared_ptr<BaseSocket> SocketFactory::CreateServerSocket(const int32_t socketId)
{
    IAM_LOGI("start.");
    return Common::MakeShared<ServerSocket>(socketId);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
