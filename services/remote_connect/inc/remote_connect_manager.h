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

#ifndef IAM_REMOTE_CONNECT_MANAGER_H
#define IAM_REMOTE_CONNECT_MANAGER_H

#include <cstdint>
#include <string>

#include "attributes.h"
#include "iam_common_defines.h"

#include "remote_connect_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteConnectionManager {
public:
    static RemoteConnectionManager &GetInstance();
    RemoteConnectionManager() = default;
    virtual ~RemoteConnectionManager() = default;

    ResultCode OpenConnection(const std::string &connectionName,
        std::string remoteNetworkId, uint32_t tokenId);
    ResultCode CloseConnection(const std::string &connectionName);
    ResultCode RegisterConnectionListener(const std::string &connectionName,
        const std::string &endPointName, const std::shared_ptr<ConnectionListener> &listener);
    ResultCode RegisterConnectionListener(const std::string &endPointName,
        const std::shared_ptr<ConnectionListener> &listener);
    ResultCode UnregisterConnectionListener(const std::string &connectionName,
        const std::string &endPointName);
    ResultCode UnregisterConnectionListener(const std::string &endPointName);
    ResultCode SendMessage(const std::string &connectionName,
        const std::string &srcEndPoint, const std::string &destEndPoint,
        const std::shared_ptr<Attributes> &attributes, MsgCallback &callback);
    void Start();
    void Stop();
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_REMOTE_CONNECT_MANAGER_H
