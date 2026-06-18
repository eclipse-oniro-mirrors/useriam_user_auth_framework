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

#include "soft_bus_server_socket.h"

#include "remote_connect_listener_manager.h"

#define LOG_FILE_ID LOG_FILE_SOFT_BUS_SERVER_SOCKET
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
ServerSocket::ServerSocket(const int32_t socketId)
    : BaseSocket(socketId)
{
    IAM_LOGI("server socket id is %{public}d.", socketId);
}

ResultCode ServerSocket::SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback)
{
    IAM_LOGI("start.");
    int32_t socketId = GetSocketIdByClientConnectionName(connectionName);
    if (socketId == INVALID_SOCKET_ID) {
        IAM_LOGE("socket id is invalid");
        return GENERAL_ERROR;
    }

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

void ServerSocket::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    if (info.networkId == nullptr) {
        IAM_LOGE("networkId is invalid.");
        return;
    }

    std::string peerNetworkId(info.networkId);
    AddServerSocket(socketId, peerNetworkId);
}

void ServerSocket::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    std::string connectionName = GetClientConnectionName(socketId);
    if (!connectionName.empty()) {
        RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    }
    DeleteServerSocket(socketId);
    DeleteClientConnection(socketId);
}

void ServerSocket::OnBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
    std::string networkId = GetNetworkIdBySocketId(socketId);
    if (networkId.empty()) {
        IAM_LOGE("networkId id is null, socketId:%{public}d.", socketId);
        return;
    }

    std::shared_ptr<SoftBusMessage> softBusMessage = ParseMessage(networkId, data, dataLen);
    if (softBusMessage == nullptr) {
        IAM_LOGE("serverSocket parse message fail.");
        return;
    }

    bool ack = softBusMessage->GetAckFlag();
    std::string connectionName = softBusMessage->GetConnectionName();
    if (ack == false && !connectionName.empty()) {
        AddClientConnection(socketId, connectionName);
    }

    ResultCode ret = ProcDataReceive(socketId, softBusMessage);
    if (ret != SUCCESS) {
        IAM_LOGE("HandleDataReceive fail, socketId:%{public}d.", socketId);
        return;
    }
}

void ServerSocket::OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount)
{
    IAM_LOGI("start, socket id is %{public}d", socketId);
}

void ServerSocket::AddServerSocket(const int32_t socketId, const std::string &networkId)
{
    IAM_LOGI("start, socketId %{public}d.", socketId);
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    auto iter = serverSocketBindMap_.find(socketId);
    if (iter == serverSocketBindMap_.end()) {
        serverSocketBindMap_.insert(std::pair<int32_t, std::string>(socketId, networkId));
    } else {
        iter->second = networkId;
    }
}

void ServerSocket::DeleteServerSocket(const int32_t socketId)
{
    IAM_LOGI("start, socketId %{public}d.", socketId);
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    auto iter = serverSocketBindMap_.find(socketId);
    if (iter != serverSocketBindMap_.end()) {
        serverSocketBindMap_.erase(iter);
    }
}

std::string ServerSocket::GetNetworkIdBySocketId(int32_t socketId)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(socketId != INVALID_SOCKET_ID, "");

    std::lock_guard<std::recursive_mutex> lock(socketMutex_);
    std::string networkId;
    auto iter = serverSocketBindMap_.find(socketId);
    if (iter != serverSocketBindMap_.end()) {
        networkId = iter->second;
    }
    return networkId;
}

void ServerSocket::AddClientConnection(const int32_t socketId, const std::string &connectionName)
{
    IAM_LOGI("add socketId %{public}d connectionName %{public}s.", socketId, connectionName.c_str());
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    auto iter = clientConnectionMap_.find(socketId);
    if (iter == clientConnectionMap_.end()) {
        clientConnectionMap_.insert(std::pair<int32_t, std::string>(socketId, connectionName));
    }
}

void ServerSocket::DeleteClientConnection(const int32_t socketId)
{
    IAM_LOGI("start, socketId %{public}d.", socketId);
    IF_FALSE_LOGE_AND_RETURN(socketId != INVALID_SOCKET_ID);

    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    auto iter = clientConnectionMap_.find(socketId);
    if (iter != clientConnectionMap_.end()) {
        std::string connectionName = iter->second;
        IAM_LOGI("delete socketId %{public}d connectionName %{public}s.", socketId, connectionName.c_str());
        clientConnectionMap_.erase(iter);
    }
}

std::string ServerSocket::GetClientConnectionName(const int32_t socketId)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(socketId != INVALID_SOCKET_ID, "");

    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    std::string ConnectionName;
    auto iter = clientConnectionMap_.find(socketId);
    if (iter != clientConnectionMap_.end()) {
        ConnectionName = iter->second;
    }
    return ConnectionName;
}

int32_t ServerSocket::GetSocketIdByClientConnectionName(const std::string &connectionName)
{
    std::lock_guard<std::recursive_mutex> lock(connectionMutex_);
    int32_t socketId = INVALID_SOCKET_ID;
    for (const auto &iter : clientConnectionMap_) {
        if (iter.second == connectionName) {
            socketId = iter.first;
            break;
        }
    }

    return socketId;
}

std::string ServerSocket::GetConnectionName()
{
    return "";
}

std::string ServerSocket::GetNetworkId()
{
    return "";
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS