/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "remote_connect_manager.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_REMOTE_CONNECT_MANAGER_DYNAMIC
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

RemoteConnectionManager &RemoteConnectionManager::GetInstance()
{
    static RemoteConnectionManager instance;
    return instance;
}

ResultCode RemoteConnectionManager::OpenConnection(const std::string &connectionName,
    std::string remoteNetworkId, uint32_t tokenId)
{
    IAM_LOGE("Dynamic load mode: remote connection not supported");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::CloseConnection(const std::string &connectionName)
{
    IAM_LOGE("Dynamic load mode: skip close connection");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::RegisterConnectionListener(const std::string &connectionName,
    const std::string &endPointName, const std::shared_ptr<ConnectionListener> &listener)
{
    IAM_LOGE("Dynamic load mode: register connection listener not supported");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::RegisterConnectionListener(const std::string &endPointName,
    const std::shared_ptr<ConnectionListener> &listener)
{
    IAM_LOGE("Dynamic load mode: register connection listener not supported");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::UnregisterConnectionListener(const std::string &connectionName,
    const std::string &endPointName)
{
    IAM_LOGD("Dynamic load mode: skip unregister connection listener");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::UnregisterConnectionListener(const std::string &endPointName)
{
    IAM_LOGD("Dynamic load mode: skip unregister connection listener");
    return GENERAL_ERROR;
}

ResultCode RemoteConnectionManager::SendMessage(const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint,
    const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGE("Dynamic load mode: send message not supported");
    return GENERAL_ERROR;
}

void RemoteConnectionManager::Start()
{
    IAM_LOGD("Dynamic load mode: skip start");
}

void RemoteConnectionManager::Stop()
{
    IAM_LOGD("Dynamic load mode: skip stop");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS