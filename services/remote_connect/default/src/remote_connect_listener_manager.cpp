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

#include "remote_connect_listener_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_REMOTE_CONNECT_LISTENER_MANAGER
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const char *GLOBAL_CONNECTION_NAME = "GLOBAL";
}
bool RemoteConnectListenerManager::ListenerInfo::operator==(const ListenerInfo &other) const
{
    bool compareRet = endPointName == other.endPointName &&
        (connectionName == other.connectionName || connectionName == GLOBAL_CONNECTION_NAME);
    return compareRet;
}

RemoteConnectListenerManager &RemoteConnectListenerManager::GetInstance()
{
    static RemoteConnectListenerManager instance;
    return instance;
}

ResultCode RemoteConnectListenerManager::RegisterListener(const std::string &connectionName,
    const std::string &endPointName, const std::shared_ptr<ConnectionListener> &listener)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    IF_FALSE_LOGE_AND_RETURN_VAL(listener != nullptr, GENERAL_ERROR);
    IAM_LOGI("RegisterListener connectionName:%{public}s, endPointName:%{public}s", connectionName.c_str(),
        endPointName.c_str());

    ListenerInfo info = { connectionName, endPointName, listener };
    auto it = std::find(listeners_.begin(), listeners_.end(), info);
    if (it != listeners_.end()) {
        IAM_LOGE("listener already exist");
        return GENERAL_ERROR;
    }

    listeners_.push_back(info);
    return SUCCESS;
}

ResultCode RemoteConnectListenerManager::RegisterListener(const std::string &endPointName,
    const std::shared_ptr<ConnectionListener> &listener)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    return RegisterListener(GLOBAL_CONNECTION_NAME, endPointName, listener);
}

ResultCode RemoteConnectListenerManager::UnregisterListener(const std::string &connectionName,
    const std::string &endPointName)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    IAM_LOGI("UnregisterListener connectionName:%{public}s, endPointName:%{public}s", connectionName.c_str(),
        endPointName.c_str());
    ListenerInfo info = { connectionName, endPointName };
    auto it = std::find(listeners_.begin(), listeners_.end(), info);
    if (it == listeners_.end()) {
        IAM_LOGE("listener not exist");
        return GENERAL_ERROR;
    }

    listeners_.erase(it);
    return SUCCESS;
}

ResultCode RemoteConnectListenerManager::UnregisterListener(const std::string &endPointName)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    return UnregisterListener(GLOBAL_CONNECTION_NAME, endPointName);
}

std::shared_ptr<ConnectionListener> RemoteConnectListenerManager::FindListener(const std::string &connectionName,
    const std::string &endPointName)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    ListenerInfo info = { connectionName, endPointName };
    auto it = std::find(listeners_.begin(), listeners_.end(), info);
    if (it == listeners_.end()) {
        IAM_LOGE("connectionName:%{public}s, endPointName:%{public}s, listener not exist", connectionName.c_str(),
            endPointName.c_str());
        return nullptr;
    }
    return it->listener;
}

void RemoteConnectListenerManager::OnConnectionDown(const std::string &connectionName)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    IAM_LOGI("OnConnectionDown connectionName:%{public}s", connectionName.c_str());
    for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
        if (it->listener == nullptr) {
            IAM_LOGE("it->listener is null");
            continue;
        }
        if (it->connectionName == connectionName) {
            IAM_LOGI("notify listener endPointName:%{public}s", it->endPointName.c_str());
            it->listener->OnConnectStatus(connectionName, ConnectStatus::DISCONNECTED);
        }
    }
    listeners_.erase(std::remove_if(listeners_.begin(), listeners_.end(),
        [&](ListenerInfo item) { return item.connectionName == connectionName; }),
        listeners_.end());
    IAM_LOGI("OnConnectionDown end");
}

void RemoteConnectListenerManager::OnConnectionUp(const std::string &connectionName)
{
    std::lock_guard<std::recursive_mutex> lock(listenerMutex_);
    IAM_LOGI("OnConnectionUp connectionName:%{public}s", connectionName.c_str());
    for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
        if (it->connectionName == connectionName) {
            if (it->listener == nullptr) {
                IAM_LOGE("it->listener is null");
                continue;
            }
            IAM_LOGI("notify listener endPointName:%{public}s", it->endPointName.c_str());
            it->listener->OnConnectStatus(connectionName, ConnectStatus::CONNECTED);
        }
    }
    IAM_LOGI("OnConnectionUp end");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS