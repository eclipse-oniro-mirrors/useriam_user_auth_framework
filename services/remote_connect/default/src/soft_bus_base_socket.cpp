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

#include "soft_bus_base_socket.h"

#include <cinttypes>

#include "iam_logger.h"
#include "remote_connect_listener_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_BASE_SOCKET

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace OHOS::DistributedHardware;
const std::string USERIAM_PACKAGE_NAME = "ohos.useriam";
static constexpr uint32_t REPLY_TIMER_LEN_MS = 5 * 1000; // 5s
static constexpr uint32_t INVALID_TIMER_ID = 0;
static std::recursive_mutex g_seqMutex;
static uint32_t g_messageSeq = 0;

BaseSocket::BaseSocket(const int32_t socketId)
    : socketId_(socketId)
{
    currTraceInfo_.msgType = -1;
    currTraceInfo_.socketId = socketId;
    IAM_LOGI("create socket id %{public}d.", socketId_);
}

BaseSocket::~BaseSocket()
{
    Shutdown(socketId_);
    IAM_LOGI("close socket id %{public}d.", socketId_);
}

int32_t BaseSocket::GetSocketId()
{
    return socketId_;
}

RemoteConnectFaultTrace BaseSocket::GetCurrTraceInfo()
{
    return currTraceInfo_;
}

void BaseSocket::InsertMsgCallback(uint32_t messageSeq, const std::string &connectionName,
    const MsgCallback &callback, uint32_t timerId)
{
    IAM_LOGD("start. messageSeq:%{public}u, timerId:%{public}u", messageSeq, timerId);
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    CallbackInfo callbackInfo = {
        .connectionName = connectionName,
        .msgCallback = callback,
        .timerId = timerId,
        .sendTime = std::chrono::steady_clock::now()
    };
    callbackMap_.insert(std::pair<int32_t, CallbackInfo>(messageSeq, callbackInfo));
}

void BaseSocket::RemoveMsgCallback(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    callbackMap_.erase(messageSeq);
}

std::string BaseSocket::GetConnectionName(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    std::string connectionName;
    auto iter = callbackMap_.find(messageSeq);
    if (iter != callbackMap_.end()) {
        connectionName = iter->second.connectionName;
    }
    return connectionName;
}

MsgCallback BaseSocket::GetMsgCallback(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    MsgCallback callback = nullptr;
    auto iter = callbackMap_.find(messageSeq);
    if (iter != callbackMap_.end()) {
        callback = iter->second.msgCallback;
    }
    return callback;
}

void BaseSocket::PrintTransferDuration(uint32_t messageSeq)
{
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    auto iter = callbackMap_.find(messageSeq);
    if (iter == callbackMap_.end()) {
        IAM_LOGE("message seq not found");
        return;
    }

    auto receiveAckTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(receiveAckTime - iter->second.sendTime);
    IAM_LOGI("messageSeq:%{public}u MessageTransferDuration:%{public}" PRIu64 " ms", messageSeq,
        static_cast<uint64_t>(duration.count()));
}

uint32_t BaseSocket::GetReplyTimer(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    std::lock_guard<std::recursive_mutex> lock(callbackMutex_);
    uint32_t timerId = 0;
    auto iter = callbackMap_.find(messageSeq);
    if (iter != callbackMap_.end()) {
        timerId = iter->second.timerId;
    }
    return timerId;
}

uint32_t BaseSocket::StartReplyTimer(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    uint32_t timerId = GetReplyTimer(messageSeq);
    if (timerId != INVALID_TIMER_ID) {
        IAM_LOGI("timer is already start");
        return timerId;
    }

    timerId = RelativeTimer::GetInstance().Register(
        [weakSelf = weak_from_this(), messageSeq, socketId = socketId_] {
            auto self = weakSelf.lock();
            if (self == nullptr) {
                IAM_LOGE("socket %{public}d is released", socketId);
                return;
            }
            self->ReplyTimerTimeOut(messageSeq);
        },
        REPLY_TIMER_LEN_MS);

    return timerId;
}

void BaseSocket::StopReplyTimer(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    uint32_t timerId = GetReplyTimer(messageSeq);
    if (timerId == INVALID_TIMER_ID) {
        IAM_LOGI("timer is already stop");
        return;
    }

    RelativeTimer::GetInstance().Unregister(timerId);
}

void BaseSocket::ReplyTimerTimeOut(uint32_t messageSeq)
{
    IAM_LOGD("start. messageSeq:%{public}u", messageSeq);
    std::string connectionName = GetConnectionName(messageSeq);
    if (connectionName.empty()) {
        IAM_LOGE("GetMsgCallback connectionName fail");
        return;
    }
    currTraceInfo_.reason = "ack time out";
    ReportConnectFaultTrace(currTraceInfo_);

    RemoteConnectListenerManager::GetInstance().OnConnectionDown(connectionName);
    RemoveMsgCallback(messageSeq);
    IAM_LOGI("reply timer is timeout, messageSeq:%{public}u", messageSeq);
}

int32_t BaseSocket::GetMessageSeq()
{
    IAM_LOGD("start.");
    std::lock_guard<std::recursive_mutex> lock(g_seqMutex);
    g_messageSeq++;
    return g_messageSeq;
}

ResultCode BaseSocket::SetDeviceNetworkId(const std::string networkId, std::shared_ptr<Attributes> &attributes)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes != nullptr, INVALID_PARAMETERS);

    bool setDeviceNetworkIdRet = attributes->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, networkId);
    if (setDeviceNetworkIdRet == false) {
        IAM_LOGE("SetStringValue fail");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

void BaseSocket::RefreshTraceInfo(const std::string &connectionName, int32_t msgType, bool ack, uint32_t messageSeq)
{
    currTraceInfo_.connectionName = connectionName;
    currTraceInfo_.msgType = msgType;
    currTraceInfo_.ack = ack;
    currTraceInfo_.messageSeq = messageSeq;
}

ResultCode BaseSocket::SendRequest(const ConnectionInfo &connectionInfo)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(connectionInfo.attributes != nullptr, INVALID_PARAMETERS);
    IF_FALSE_LOGE_AND_RETURN_VAL(connectionInfo.socketId != INVALID_SOCKET_ID, INVALID_PARAMETERS);

    int32_t messageSeq = GetMessageSeq();
    int32_t msgType = -1;
    // remote pin authentication may not contain the msgType parameter, no need to check the result
    connectionInfo.attributes->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    RefreshTraceInfo(connectionInfo.connectionName, msgType, false, messageSeq);
    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(messageSeq,
        connectionInfo.connectionName, connectionInfo.srcEndPoint, connectionInfo.destEndPoint,
        connectionInfo.attributes);
    if (softBusMessage == nullptr) {
        IAM_LOGE("softBusMessage is nullptr");
        return GENERAL_ERROR;
    }

    std::shared_ptr<Attributes> request = softBusMessage->CreateMessage(false);
    if (request == nullptr) {
        IAM_LOGE("creatMessage fail");
        return GENERAL_ERROR;
    }

    std::vector<uint8_t> data = request->Serialize();
    int ret = SendBytes(connectionInfo.socketId, data.data(), data.size());
    if (ret != SUCCESS) {
        IAM_LOGE("fail to send message, result= %{public}d", ret);
        return GENERAL_ERROR;
    }

    uint32_t timerId = StartReplyTimer(messageSeq);
    if (timerId == INVALID_TIMER_ID) {
        IAM_LOGE("create reply timer fail");
        return GENERAL_ERROR;
    }

    InsertMsgCallback(messageSeq, connectionInfo.connectionName, connectionInfo.callback, timerId);
    IAM_LOGI("SendRequest success.");
    return SUCCESS;
}

ResultCode BaseSocket::SendResponse(const int32_t socketId, const std::string &connectionName,
    const std::string &srcEndPoint, const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes,
    uint32_t messageSeq)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(attributes != nullptr, INVALID_PARAMETERS);
    IF_FALSE_LOGE_AND_RETURN_VAL(socketId != INVALID_SOCKET_ID, INVALID_PARAMETERS);
    int32_t msgType = -1;
    // remote pin authentication may not contain the msgType parameter, no need to check the result
    attributes->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    RefreshTraceInfo(connectionName, msgType, true, messageSeq);

    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(messageSeq,
        connectionName, srcEndPoint, destEndPoint, attributes);
    if (softBusMessage == nullptr) {
        IAM_LOGE("softBusMessage is nullptr");
        return GENERAL_ERROR;
    }

    std::shared_ptr<Attributes> response = softBusMessage->CreateMessage(true);
    if (response == nullptr) {
        IAM_LOGE("creatMessage fail");
        return GENERAL_ERROR;
    }

    std::vector<uint8_t> data = response->Serialize();
    int ret = SendBytes(socketId, data.data(), data.size());
    if (ret != SUCCESS) {
        IAM_LOGE("fail to send message, result= %{public}d", ret);
        return GENERAL_ERROR;
    }

    IAM_LOGI("SendResponse success.");
    return SUCCESS;
}

std::shared_ptr<SoftBusMessage> BaseSocket::ParseMessage(const std::string &networkId,
    const void *message, uint32_t messageLen)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(message != nullptr, nullptr);
    IF_FALSE_LOGE_AND_RETURN_VAL(messageLen != 0, nullptr);

    std::shared_ptr<SoftBusMessage> softBusMessage = Common::MakeShared<SoftBusMessage>(0, "", "", "", nullptr);
    if (softBusMessage == nullptr) {
        IAM_LOGE("softBusMessage is nullptr");
        return nullptr;
    }

    std::shared_ptr<Attributes> attributes = softBusMessage->ParseMessage(message, messageLen);
    if (attributes == nullptr) {
        IAM_LOGE("parseMessage fail");
        return nullptr;
    }
    int32_t msgType = -1;
    // remote pin authentication may not contain the msgType parameter, no need to check the result
    attributes->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    RefreshTraceInfo(softBusMessage->GetConnectionName(), msgType, softBusMessage->GetAckFlag(),
        softBusMessage->GetMessageSeq());

    int32_t ret = SetDeviceNetworkId(networkId, attributes);
    if (ret != SUCCESS) {
        IAM_LOGE("SetDeviceNetworkId fail");
        return nullptr;
    }

    IAM_LOGD("ParseMessage success.");
    return softBusMessage;
}

void BaseSocket::ProcessMessage(std::shared_ptr<SoftBusMessage> softBusMessage, std::shared_ptr<Attributes> response)
{
    IF_FALSE_LOGE_AND_RETURN(softBusMessage != nullptr);
    IF_FALSE_LOGE_AND_RETURN(response != nullptr);

    bool setResultCode = response->SetInt32Value(Attributes::ATTR_RESULT_CODE, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN(setResultCode);

    uint32_t messageVersion = softBusMessage->GetMessageVersion();
    if (messageVersion != DEFAULT_MESSAGE_VERSION) {
        IAM_LOGE("support message version %{public}u, receive message version %{public}u", DEFAULT_MESSAGE_VERSION,
            messageVersion);
        std::vector<uint32_t> supportedVersions = { DEFAULT_MESSAGE_VERSION };
        bool setSupportedVersionsRet = response->SetUint32ArrayValue(Attributes::ATTR_SUPPORTED_MSG_VERSION,
            supportedVersions);
        IF_FALSE_LOGE_AND_RETURN(setSupportedVersionsRet);
        return;
    }

    std::string connectionName = softBusMessage->GetConnectionName();
    std::string destEndPoint = softBusMessage->GetDestEndPoint();

    std::shared_ptr<ConnectionListener> connectionListener =
        RemoteConnectListenerManager::GetInstance().FindListener(connectionName, destEndPoint);
    if (connectionListener == nullptr) {
        IAM_LOGE("connectionListener is nullptr");
        return;
    }

    auto beginTime = std::chrono::steady_clock::now();
    connectionListener->OnMessage(connectionName, destEndPoint, softBusMessage->GetAttributes(), response);
    auto endTime = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - beginTime);
    IAM_LOGI("messageSeq:%{public}u ProcessMessageDuration:%{public}" PRIu64 " ms", softBusMessage->GetMessageSeq(),
        static_cast<uint64_t>(duration.count()));
}

ResultCode BaseSocket::ProcDataReceive(const int32_t socketId, std::shared_ptr<SoftBusMessage> &softBusMessage)
{
    IAM_LOGD("start.");
    IF_FALSE_LOGE_AND_RETURN_VAL(softBusMessage != nullptr, INVALID_PARAMETERS);
    IF_FALSE_LOGE_AND_RETURN_VAL(socketId != INVALID_SOCKET_ID, INVALID_PARAMETERS);

    std::shared_ptr<Attributes> request = softBusMessage->GetAttributes();
    if (request == nullptr) {
        IAM_LOGE("GetAttributes fail");
        return GENERAL_ERROR;
    }

    uint32_t messageSeq = softBusMessage->GetMessageSeq();
    bool ack = softBusMessage->GetAckFlag();
    if (ack == true) {
        PrintTransferDuration(messageSeq);
        MsgCallback callback = GetMsgCallback(messageSeq);
        if (callback == nullptr) {
            IAM_LOGE("GetMsgCallback fail");
            return GENERAL_ERROR;
        }

        callback(request);
        StopReplyTimer(messageSeq);
        RemoveMsgCallback(messageSeq);
    } else {
        std::string connectionName = softBusMessage->GetConnectionName();
        std::string srcEndPoint = softBusMessage->GetSrcEndPoint();
        std::string destEndPoint = softBusMessage->GetDestEndPoint();

        std::shared_ptr<Attributes> response = Common::MakeShared<Attributes>();
        if (response == nullptr) {
            IAM_LOGE("create fail");
            return GENERAL_ERROR;
        }

        ProcessMessage(softBusMessage, response);

        SendResponse(socketId, connectionName, destEndPoint, srcEndPoint, response, messageSeq);
    }

    IAM_LOGI("ProcDataReceive success.");
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS