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

#include "remote_executor_proxy.h"

#include <functional>
#include <mutex>

#include "co_auth_client.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "thread_handler.h"

#define LOG_FILE_ID LOG_FILE_REMOTE_EXECUTOR_PROXY
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteExecutorProxyCallback : public ExecutorRegisterCallback, public NoCopyable {
public:
    explicit RemoteExecutorProxyCallback(std::weak_ptr<RemoteExecutorProxy> callback) : callback_(callback)
    {
    }
    ~RemoteExecutorProxyCallback() override = default;

    void OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) override
    {
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
        callback->OnMessengerReady(messenger, publicKey, templateIdList);
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &commandAttrs) override
    {
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
        return callback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    }
    int32_t OnEndExecute(uint64_t scheduleId, const Attributes &commandAttrs) override
    {
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
        return callback->OnEndExecute(scheduleId, commandAttrs);
    }

    int32_t OnSetProperty(const Attributes &properties) override
    {
        IAM_LOGE("OnSetProperty is not supported");
        return GENERAL_ERROR;
    }

    int32_t OnGetProperty(const Attributes &conditions, Attributes &results) override
    {
        IAM_LOGE("OnGetProperty is not supported");
        return GENERAL_ERROR;
    }

    int32_t OnSendData(uint64_t scheduleId, const Attributes &data) override
    {
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
        return callback->OnSendData(scheduleId, data);
    }

private:
    std::weak_ptr<RemoteExecutorProxy> callback_;
};

class RemoteExecutorProxyMessageCallback : public ConnectionListener, public NoCopyable {
public:
    explicit RemoteExecutorProxyMessageCallback(std::weak_ptr<RemoteExecutorProxy> callback)
        : callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }
    ~RemoteExecutorProxyMessageCallback() = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());

        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
        callback->OnMessage(connectionName, srcEndPoint, request, reply);
    }

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) override
    {
        IAM_LOGI("connectionName: %{public}s, connectStatus %{public}d", connectionName.c_str(), connectStatus);

        IF_FALSE_LOGE_AND_RETURN(connectStatus == ConnectStatus::DISCONNECTED);
        IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
        threadHandler_->PostTask([connectionName, connectStatus, callbackTemp = callback_, this]() {
            IAM_LOGI("OnConnectStatus process begin");
            auto callback = callbackTemp.lock();
            IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
            callback->OnConnectStatus(connectionName, connectStatus);
            IAM_LOGI("OnConnectStatus process success");
        });

        IAM_LOGI("task posted");
    }

private:
    std::weak_ptr<RemoteExecutorProxy> callback_;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteExecutorProxy::RemoteExecutorProxy(std::string connectionName, ExecutorInfo registerInfo)
    : connectionName_(connectionName),
      registerInfo_(registerInfo),
      endPointName_(EXECUTOR_PROXY_ENDPOINT_NAME)
{
}

RemoteExecutorProxy::~RemoteExecutorProxy()
{
    IAM_LOGI("start");

    RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    CoAuthClient::GetInstance().Unregister(executorIndex_);

    IAM_LOGI("success");
}

ResultCode RemoteExecutorProxy::Start()
{
    IAM_LOGI("start");
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        connectionCallback_ = Common::MakeShared<RemoteExecutorProxyMessageCallback>(weak_from_this());
        IF_FALSE_LOGE_AND_RETURN_VAL(connectionCallback_ != nullptr, GENERAL_ERROR);

        ResultCode registerResult = RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_,
            endPointName_, connectionCallback_);
        IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, GENERAL_ERROR);

        executorCallback_ = Common::MakeShared<RemoteExecutorProxyCallback>(weak_from_this());
        IF_FALSE_LOGE_AND_RETURN_VAL(executorCallback_ != nullptr, GENERAL_ERROR);
    }

    uint64_t executorIndex = CoAuthClient::GetInstance().Register(registerInfo_, executorCallback_);
    IF_FALSE_LOGE_AND_RETURN_VAL(executorIndex != INVALID_EXECUTOR_INDEX, GENERAL_ERROR);

    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        executorIndex_ = executorIndex;
    }

    IAM_LOGI("success");
    return ResultCode::SUCCESS;
}

void RemoteExecutorProxy::OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    IF_FALSE_LOGE_AND_RETURN(connectionName_ == connectionName);
    IF_FALSE_LOGE_AND_RETURN(request != nullptr);
    IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

    int32_t msgType;
    bool getMsgTypeRet = request->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    IF_FALSE_LOGE_AND_RETURN(getMsgTypeRet);

    int32_t resultCode = ResultCode::GENERAL_ERROR;
    switch (msgType) {
        case MessageType::EXECUTOR_SEND_DATA:
            resultCode = ProcSendDataMsg(*request);
            break;
        case MessageType::EXECUTOR_FINISH:
            resultCode = ProcFinishMsg(*request);
            break;
        default:
            IAM_LOGE("unsupported message type: %{public}d", msgType);
            break;
    }

    IF_FALSE_LOGE_AND_RETURN(resultCode == ResultCode::SUCCESS);
    bool setResultCodeRet = reply->SetInt32Value(Attributes::ATTR_RESULT_CODE, ResultCode::SUCCESS);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet);

    IAM_LOGI("success");
}

void RemoteExecutorProxy::OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus)
{
}

void RemoteExecutorProxy::OnMessengerReady(const std::shared_ptr<ExecutorMessenger> &messenger,
    const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    messenger_ = messenger;
    IAM_LOGI("success");
}

int32_t RemoteExecutorProxy::OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &command)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start, scheduleId: %{public}s", GET_MASKED_STRING(scheduleId).c_str());

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(command.Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMessageTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::BEGIN_EXECUTE);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMessageTypeRet, GENERAL_ERROR);

    bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleIdRet, GENERAL_ERROR);

    std::vector<uint8_t> collectorMessage;
    bool getCollectorMessageRet = request->GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, collectorMessage);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCollectorMessageRet, GENERAL_ERROR);

    bool setScheduleDataRet = request->SetUint8ArrayValue(Attributes::ATTR_SCHEDULE_DATA, collectorMessage);
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleDataRet, GENERAL_ERROR);

    MsgCallback msgCallback = [self = weak_from_this(), scheduleId](const std::shared_ptr<Attributes> &reply) {
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        auto sharedSelf = self.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedSelf != nullptr);
        int32_t resultCode;
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);
        if (resultCode != ResultCode::SUCCESS) {
            IAM_LOGE("scheduleId %{public}s begin execute failed", GET_MASKED_STRING(scheduleId).c_str());
            sharedSelf->OnErrorFinish(scheduleId);
            return;
        }
        IAM_LOGI("scheduleId %{public}s begin execute success", GET_MASKED_STRING(scheduleId).c_str());
    };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_SERVICE_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success, scheduleId %{public}s", GET_MASKED_STRING(scheduleId).c_str());
    return ResultCode::SUCCESS;
}

int32_t RemoteExecutorProxy::OnEndExecute(uint64_t scheduleId, const Attributes &command)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start, scheduleId: %{public}s", GET_MASKED_STRING(scheduleId).c_str());

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(command.Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMessageTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::END_EXECUTE);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMessageTypeRet, GENERAL_ERROR);

    bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleIdRet, GENERAL_ERROR);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_SERVICE_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success, scheduleId %{public}s", GET_MASKED_STRING(scheduleId).c_str());
    return ResultCode::SUCCESS;
}

int32_t RemoteExecutorProxy::OnSendData(uint64_t scheduleId, const Attributes &data)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(data.Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMessageTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::SEND_DATA_TO_EXECUTOR);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMessageTypeRet, GENERAL_ERROR);

    bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleIdRet, GENERAL_ERROR);

    MsgCallback msgCallback = [weakThis = weak_from_this(), scheduleId](const std::shared_ptr<Attributes> &reply) {
        int32_t resultCode;
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);

        if (resultCode != ResultCode::SUCCESS) {
            IAM_LOGE("send data to executor failed");
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            sharedThis->OnErrorFinish(scheduleId);
            return;
        }
    };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        EXECUTOR_STUB_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return ResultCode::SUCCESS;
}

int32_t RemoteExecutorProxy::ProcSendDataMsg(Attributes &data)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    uint64_t scheduleId;
    bool getScheduleIdRet = data.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);

    int32_t dstRole;
    bool getDstRoleRet = data.GetInt32Value(Attributes::ATTR_DEST_ROLE, dstRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getDstRoleRet, GENERAL_ERROR);

    auto msg = AuthMessage::As(data.Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(msg != nullptr, GENERAL_ERROR);

    IAM_LOGI("scheduleId %{public}s send data", GET_MASKED_STRING(scheduleId).c_str());
    IF_FALSE_LOGE_AND_RETURN_VAL(messenger_ != nullptr, GENERAL_ERROR);
    int32_t ret = messenger_->SendData(scheduleId, static_cast<ExecutorRole>(dstRole), msg);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success");
    return ret;
}

int32_t RemoteExecutorProxy::ProcFinishMsg(Attributes &data)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    uint64_t scheduleId;
    bool getScheduleIdRet = data.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);

    int32_t resultCode;
    bool getResultCodeRet = data.GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet, GENERAL_ERROR);

    IF_FALSE_LOGE_AND_RETURN_VAL(messenger_ != nullptr, GENERAL_ERROR);

    IAM_LOGI("scheduleId %{public}s proc finish code %{public}d", GET_MASKED_STRING(scheduleId).c_str(), resultCode);
    int32_t ret = messenger_->Finish(scheduleId, static_cast<ResultCode>(resultCode), data);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, GENERAL_ERROR);
    IAM_LOGI("success");
    return ret;
}

void RemoteExecutorProxy::OnErrorFinish(uint64_t scheduleId)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    Attributes request;

    bool setScheduleIdRet = request.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN(setScheduleIdRet);

    bool setResultCodeRet = request.SetInt32Value(Attributes::ATTR_RESULT_CODE, ResultCode::GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet);

    ProcFinishMsg(request);
    IAM_LOGI("success");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS