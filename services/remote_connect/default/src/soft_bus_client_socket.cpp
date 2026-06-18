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

#include "soft_bus_client_socket.h"

#include "relative_timer.h"
#include "remote_connect_listener_manager.h"
#include "remote_connect_manager.h"
#include "remote_message.h"
#include "thread_handler_manager.h"

#define LOG_FILE_ID LOG_FILE_SOFT_BUS_CLIENT_SOCKET
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
const uint32_t KEEP_ALIVE_INTERVAL = 1000; // 1s
}
ClientSocket::ClientSocket(const int32_t socketId)
    : BaseSocket(socketId)
{
    IAM_LOGI("client socket id is %{public}d.", socketId);
}

ClientSocket::~ClientSocket()
{
    if (keepAliveTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(keepAliveTimerId_.value());
    }
}

ResultCode ClientSocket::SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGD("start.");
    int32_t socketId = GetSocketId();
    if (socketId == INVALID_SOCKET_ID) {
        IAM_LOGE("socket id is invalid");
        return GENERAL_ERROR;
    }

    RefreshKeepAliveTimer();
    const ConnectionInfo connectionInfo = {
        .socketId = socketId,
        .connectionName = connectionName,
        .srcEndPoint = srcEndPoint,
        .destEndPoint = destEndPoint,
        .attributes = attributes,
        .callback = callback
    };
    return SendRequest(connectionInfo);
}

void ClientSocket::OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
}

void ClientSocket::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    std::string connectionName = GetConnectionName();
    if (!connectionName.empty()) {
        RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    }
}

void ClientSocket::OnBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGD("start, socket id is %{public}d", socketId);
    IF_FALSE_LOGE_AND_RETURN(data != nullptr);
    IF_FALSE_LOGE_AND_RETURN(dataLen != 0);

    std::string networkId = GetNetworkId();
    if (networkId.empty()) {
        IAM_LOGE("networkId id is null, socketId:%{public}d.", socketId);
        return;
    }

    std::shared_ptr<SoftBusMessage> softBusMessage = ParseMessage(networkId, data, dataLen);
    if (softBusMessage == nullptr) {
        IAM_LOGE("serverSocket parse message fail.");
        return;
    }

    ResultCode ret = ProcDataReceive(socketId, softBusMessage);
    if (ret != SUCCESS) {
        IAM_LOGE("HandleDataReceive fail, socketId:%{public}d.", socketId);
        return;
    }
}

void ClientSocket::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
}

std::string ClientSocket::GetConnectionName()
{
    return connectionName_;
}

std::string ClientSocket::GetNetworkId()
{
    return networkId_;
}

void ClientSocket::SetConnectionName(const std::string &connectionName)
{
    connectionName_ = connectionName;
}

void ClientSocket::SetNetworkId(const std::string &networkId)
{
    networkId_ = networkId;
}

void ClientSocket::RefreshKeepAliveTimer()
{
    if (keepAliveTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(keepAliveTimerId_.value());
    }
    keepAliveTimerId_ = RelativeTimer::GetInstance().Register([weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            SendKeepAliveMessage();
        }, KEEP_ALIVE_INTERVAL);
    IAM_LOGI("ConnectionName: %{public}s, keep alive timer is refreshed", connectionName_.c_str());
}

void ClientSocket::SendKeepAliveMessage()
{
    IAM_LOGI("ConnectionName: %{public}s, send keep alive message begin", connectionName_.c_str());
    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN(request != nullptr);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::KEEP_ALIVE);
    IF_FALSE_LOGE_AND_RETURN(setMsgTypeRet);

    MsgCallback sendKeepAliveCallback = [connectionName = connectionName_](const std::shared_ptr<Attributes> &) {
        IAM_LOGI("ConnectionName: %{public}s, receive keep alive message ack", connectionName.c_str());
    };
    ResultCode ret = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, CLIENT_SOCKET_ENDPOINT_NAME,
        REMOTE_SERVICE_ENDPOINT_NAME, request, sendKeepAliveCallback);
    if (ret != SUCCESS) {
        IAM_LOGE("ConnectionName: %{public}s, send keep alive message failed, connection down",
            connectionName_.c_str());
        auto threadHandler = ThreadHandlerManager::GetInstance().GetThreadHandler(SINGLETON_THREAD_NAME);
        if (threadHandler == nullptr) {
            IAM_LOGE("ConnectionName: %{public}s, threadHandler is nullptr", connectionName_.c_str());
            return;
        }
        threadHandler->PostTask(
            [connectionName = connectionName_]() {
                RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
                IAM_LOGE("ConnectionName: %{public}s, set connection down", connectionName.c_str());
            });
        return;
    }
    IAM_LOGI("ConnectionName: %{public}s, send keep alive message success", connectionName_.c_str());
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS