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

#ifndef REMOTE_CONNECT_LISTENER_MANAGER_H
#define REMOTE_CONNECT_LISTENER_MANAGER_H

#include <mutex>
#include <vector>

#include "iam_common_defines.h"
#include "remote_connect_listener.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteConnectListenerManager {
public:
    static RemoteConnectListenerManager &GetInstance();
    RemoteConnectListenerManager() = default;
    ~RemoteConnectListenerManager() = default;

    ResultCode RegisterListener(const std::string &connectionName, const std::string &endPointName,
        const std::shared_ptr<ConnectionListener> &listener);
    ResultCode RegisterListener(const std::string &endPointName, const std::shared_ptr<ConnectionListener> &listener);
    ResultCode UnregisterListener(const std::string &connectionName, const std::string &endPointName);
    ResultCode UnregisterListener(const std::string &endPointName);

    std::shared_ptr<ConnectionListener> FindListener(const std::string &connectionName,
        const std::string &endPointName);
    void OnConnectionDown(const std::string &connectionName);
    void OnConnectionUp(const std::string &connectionName);

    struct ListenerInfo {
        std::string connectionName;
        std::string endPointName;
        std::shared_ptr<ConnectionListener> listener {nullptr};

        bool operator==(const ListenerInfo &other) const;
    };

private:
    std::vector<ListenerInfo> listeners_;
    std::recursive_mutex listenerMutex_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // REMOTE_CONNECT_LISTENER_MANAGER_H