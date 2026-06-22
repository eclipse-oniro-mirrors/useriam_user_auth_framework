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

#ifndef IAM_REMOTE_CONNECT_LISTENER_H
#define IAM_REMOTE_CONNECT_LISTENER_H

#include <cstdint>
#include <string>

#include "attributes.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using MsgCallback = std::function<void(const std::shared_ptr<Attributes> &)>;

enum ConnectStatus {
    DISCONNECTED = 0,
    CONNECTED = 1,
};

class ConnectionListener {
public:
    ConnectionListener() = default;
    virtual ~ConnectionListener() = default;
    virtual void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) = 0;
    virtual void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_REMOTE_CONNECT_LISTENER_H
