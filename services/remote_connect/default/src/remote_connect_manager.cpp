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

#include "securec.h"

#include "remote_connect_manager.h"
#include "remote_connect_listener.h"
#include "remote_connect_listener_manager.h"
#include "soft_bus_manager.h"
#include "device_manager.h"

#define LOG_FILE_ID LOG_FILE_REMOTE_CONNECT_MANAGER
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::DistributedHardware;
RemoteConnectionManager &RemoteConnectionManager::GetInstance()
{
    IAM_LOGD("start.");
    static RemoteConnectionManager instance;
    return instance;
}

ResultCode RemoteConnectionManager::OpenConnection(const std::string &connectionName,
    std::string remoteNetworkId, uint32_t tokenId)
{
    IAM_LOGD("start.");
    return SoftBusManager::GetInstance().OpenConnection(connectionName, tokenId, remoteNetworkId);
}

ResultCode RemoteConnectionManager::CloseConnection(const std::string &connectionName)
{
    IAM_LOGD("start.");
    return SoftBusManager::GetInstance().CloseConnection(connectionName);
}

ResultCode RemoteConnectionManager::RegisterConnectionListener(const std::string &connectionName,
    const std::string &endPointName, const std::shared_ptr<ConnectionListener> &listener)
{
    IAM_LOGD("start.");
    return RemoteConnectListenerManager::GetInstance().RegisterListener(connectionName, endPointName, listener);
}

ResultCode RemoteConnectionManager::RegisterConnectionListener(const std::string &endPointName,
    const std::shared_ptr<ConnectionListener> &listener)
{
    IAM_LOGD("start.");
    return RemoteConnectListenerManager::GetInstance().RegisterListener(endPointName, listener);
}

ResultCode RemoteConnectionManager::UnregisterConnectionListener(const std::string &connectionName,
    const std::string &endPointName)
{
    IAM_LOGD("start.");
    return RemoteConnectListenerManager::GetInstance().UnregisterListener(connectionName, endPointName);
}

ResultCode RemoteConnectionManager::UnregisterConnectionListener(const std::string &endPointName)
{
    IAM_LOGD("start.");
    return RemoteConnectListenerManager::GetInstance().UnregisterListener(endPointName);
}

ResultCode RemoteConnectionManager::SendMessage(const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint,
    const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGD("start.");
    return SoftBusManager::GetInstance().SendMessage(connectionName,
        srcEndPoint, destEndPoint, attributes, callback);
}

void RemoteConnectionManager::Start()
{
    IAM_LOGD("RemoteConnectionManager start.");
    SoftBusManager::GetInstance().Start();
}

void RemoteConnectionManager::Stop()
{
    IAM_LOGD("RemoteConnectionManager stop.");
    SoftBusManager::GetInstance().Stop();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
