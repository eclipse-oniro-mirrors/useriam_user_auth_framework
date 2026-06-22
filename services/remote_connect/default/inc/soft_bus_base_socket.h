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

#ifndef IAM_SOFT_BUS_SOCKET_H
#define IAM_SOFT_BUS_SOCKET_H

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>
#include "socket.h"

#include "attributes.h"
#include "device_manager.h"
#include "hisysevent_adapter.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "remote_connect_listener.h"
#include "soft_bus_message.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using time_point = std::chrono::steady_clock::time_point;
class BaseSocket : public std::enable_shared_from_this<BaseSocket> {
public:
    struct ConnectionInfo {
        int32_t socketId;
        std::string connectionName;
        std::string srcEndPoint;
        std::string destEndPoint;
        std::shared_ptr<Attributes> attributes;
        MsgCallback callback;
    };

    BaseSocket(const int32_t socketId);
    virtual ~BaseSocket();
    int32_t GetSocketId();
    virtual ResultCode SendMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes, MsgCallback &callback) = 0;
    ResultCode SendRequest(const ConnectionInfo &connectionInfo);
    ResultCode SendResponse(const int32_t socketId, const std::string &connectionName,
        const std::string &srcEndPoint, const std::string &destEndPoint, const std::shared_ptr<Attributes> &attributes,
        uint32_t messageSeq);
    std::shared_ptr<SoftBusMessage> ParseMessage(const std::string &networkId,
        const void *message, uint32_t messageLen);
    ResultCode ProcDataReceive(const int32_t socketId, std::shared_ptr<SoftBusMessage> &softBusMessage);
    std::string GetConnectionName(uint32_t messageSeq);
    MsgCallback GetMsgCallback(uint32_t messageSeq);
    RemoteConnectFaultTrace GetCurrTraceInfo();

    virtual void OnBind(int32_t socketId, PeerSocketInfo info) = 0;
    virtual void OnShutdown(int32_t socketId, ShutdownReason reason) = 0;
    virtual void OnBytes(int32_t socketId, const void *data, uint32_t dataLen) = 0;
    virtual void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) = 0;

    virtual std::string GetConnectionName() = 0;
    virtual std::string GetNetworkId() = 0;

    struct CallbackInfo {
        std::string connectionName;
        MsgCallback msgCallback;
        uint32_t timerId;
        time_point sendTime;
    };

private:
    void InsertMsgCallback(uint32_t messageSeq, const std::string &connectionName,
        const MsgCallback &callback, uint32_t timerId);
    void RemoveMsgCallback(uint32_t messageSeq);

    uint32_t GetReplyTimer(uint32_t messageSeq);
    uint32_t StartReplyTimer(uint32_t messageSeq);
    void StopReplyTimer(uint32_t messageSeq);
    void ReplyTimerTimeOut(uint32_t messageSeq);
    int32_t GetMessageSeq();
    ResultCode SetDeviceNetworkId(const std::string networkId, std::shared_ptr<Attributes> &attributes);
    void PrintTransferDuration(uint32_t messageSeq);
    void ProcessMessage(std::shared_ptr<SoftBusMessage> softBusMessage, std::shared_ptr<Attributes> response);
    void RefreshTraceInfo(const std::string &connectionName, int32_t msgType, bool ack, uint32_t messageSeq);

    std::recursive_mutex callbackMutex_;
    /* <messageSeq, CallbackInfo> */
    std::map<uint32_t, CallbackInfo> callbackMap_;

    int32_t socketId_ = -1;
    RemoteConnectFaultTrace currTraceInfo_ = {};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_BUS_SOCKET_H