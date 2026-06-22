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

#include "remote_executor_stub.h"

#include "iam_check.h"
#include "schedule_node.h"

#include "context_factory.h"
#include "context_pool.h"
#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "hisysevent_adapter.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "remote_auth_service.h"
#include "remote_msg_util.h"
#include "resource_node_pool.h"
#include "schedule_resource_node_listener.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_EXECUTOR_STUB

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class RemoteExecutorStubScheduleNode : public ScheduleNode,
                                       public std::enable_shared_from_this<ScheduleNode>,
                                       public NoCopyable {
public:
    RemoteExecutorStubScheduleNode(HdiScheduleInfo &scheduleInfo, std::weak_ptr<RemoteExecutorStub> callback,
        std::weak_ptr<ResourceNode> collectorExecutor)
        : scheduleId_(scheduleInfo.scheduleId),
          callback_(callback),
          collectorExecutor_(collectorExecutor)
    {
    }

    ~RemoteExecutorStubScheduleNode()
    {
        if (resourceNodePoolListener_ != nullptr) {
            ResourceNodePool::Instance().DeregisterResourceNodePoolListener(resourceNodePoolListener_);
        }
    }

    uint64_t GetScheduleId() const override
    {
        return scheduleId_;
    }

    uint64_t GetContextId() const override
    {
        return 0;
    }

    AuthType GetAuthType() const override
    {
        return AuthType::ALL;
    }

    uint64_t GetExecutorMatcher() const override
    {
        return 0;
    }
    ScheduleMode GetScheduleMode() const override
    {
        return ScheduleMode::AUTH;
    }
    std::weak_ptr<ResourceNode> GetCollectorExecutor() const override
    {
        return collectorExecutor_;
    }
    std::weak_ptr<ResourceNode> GetVerifyExecutor() const override
    {
        static std::weak_ptr<ResourceNode> nullNode;
        return nullNode;
    }
    std::optional<std::vector<uint64_t>> GetTemplateIdList() const override
    {
        return std::nullopt;
    }
    State GetCurrentScheduleState() const override
    {
        return State::S_INIT;
    }
    std::shared_ptr<ScheduleNodeCallback> GetScheduleCallback() override
    {
        return nullptr;
    }
    int32_t GetAuthIntent() const override
    {
        return 0;
    }
    void ClearScheduleCallback() override
    {
        return;
    }
    bool StartSchedule() override
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        resourceNodePoolListener_ = Common::MakeShared<ScheduleResourceNodeListener>(weak_from_this());
        IF_FALSE_LOGE_AND_RETURN_VAL(resourceNodePoolListener_ != nullptr, false);
        bool registerRet = ResourceNodePool::Instance().RegisterResourceNodePoolListener(resourceNodePoolListener_);
        IF_FALSE_LOGE_AND_RETURN_VAL(registerRet, false);
        return true;
    }
    bool StopSchedule() override
    {
        return true;
    }
    bool StopSchedule(ResultCode errorCode) override
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        IAM_LOGI("stop schedule errorCode %{public}d", errorCode);
        auto finalResult = Common::MakeShared<Attributes>();
        IF_FALSE_LOGE_AND_RETURN_VAL(finalResult != nullptr, false);
        bool setResultCodeRet = finalResult->SetInt32Value(Attributes::ATTR_RESULT_CODE, errorCode);
        IF_FALSE_LOGE_AND_RETURN_VAL(setResultCodeRet, false);

        return ContinueSchedule(errorCode, finalResult);
    }
    bool SendMessage(ExecutorRole dstRole, const std::vector<uint8_t> &msg) override
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
        int32_t ret = callback->OnMessage(dstRole, msg);
        return ret == ResultCode::SUCCESS;
    }
    bool ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult) override
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto callback = callback_.lock();
        IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
        int32_t ret = callback->ContinueSchedule(resultCode, finalResult);
        return ret == ResultCode::SUCCESS;
    }

private:
    std::recursive_mutex mutex_;
    uint64_t scheduleId_;
    std::weak_ptr<RemoteExecutorStub> callback_;
    std::weak_ptr<ResourceNode> collectorExecutor_;
    std::shared_ptr<ResourceNodePool::ResourceNodePoolListener> resourceNodePoolListener_ {nullptr};
};

class RemoteExecutorStubMessageCallback : public ConnectionListener, public NoCopyable {
public:
    explicit RemoteExecutorStubMessageCallback(uint64_t scheduleId, std::weak_ptr<RemoteExecutorStub> callback)
        : scheduleId_(scheduleId),
          callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }
    ~RemoteExecutorStubMessageCallback() = default;

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
        IAM_LOGI("connectionName: %{public}s, connectStatus %{public}d, scheduleId "
                 "%{public}s",
            connectionName.c_str(), connectStatus, GET_MASKED_STRING(scheduleId_).c_str());

        IF_FALSE_LOGE_AND_RETURN(connectStatus == ConnectStatus::DISCONNECTED);

        IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);

        threadHandler_->PostTask([scheduleId = scheduleId_]() {
            IAM_LOGI("OnConnectStatus process begin, scheduleId %{public}s", GET_MASKED_STRING(scheduleId).c_str());

            auto request = Common::MakeShared<Attributes>();
            IF_FALSE_LOGE_AND_RETURN(request != nullptr);
            bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
            IF_FALSE_LOGE_AND_RETURN(setScheduleIdRet);

            auto reply = Common::MakeShared<Attributes>();
            IF_FALSE_LOGE_AND_RETURN(reply != nullptr);
            RemoteAuthService::GetInstance().ProcEndExecuteRequest(request, reply);
            IAM_LOGI("OnConnectStatus process success, scheduleId %{public}s", GET_MASKED_STRING(scheduleId).c_str());
        });

        IAM_LOGI("task posted");
    }

private:
    uint64_t scheduleId_;
    std::weak_ptr<RemoteExecutorStub> callback_;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteExecutorStub::RemoteExecutorStub() : endPointName_(EXECUTOR_STUB_ENDPOINT_NAME)
{
}

RemoteExecutorStub::~RemoteExecutorStub()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (connectionCallback_ != nullptr) {
        RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    }
    if (contextId_.has_value()) {
        ContextPool::Instance().Delete(contextId_.value());
    }
    IAM_LOGI("ConnectionName %{public}s RemoteExecutorStub destructed", connectionName_.c_str());
}

int32_t RemoteExecutorStub::ProcBeginExecuteRequest(Attributes &attr, RemoteExecuteTrace &trace)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    bool getScheduleIdRet = attr.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, trace.scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);
    IAM_LOGI("scheduleId %{public}s begin execute", GET_MASKED_STRING(trace.scheduleId).c_str());

    connectionCallback_ = Common::MakeShared<RemoteExecutorStubMessageCallback>(trace.scheduleId, shared_from_this());
    IF_FALSE_LOGE_AND_RETURN_VAL(connectionCallback_ != nullptr, GENERAL_ERROR);

    bool getConnectionName = attr.GetStringValue(Attributes::ATTR_CONNECTION_NAME, connectionName_);
    IF_FALSE_LOGE_AND_RETURN_VAL(getConnectionName, GENERAL_ERROR);
    trace.connectionName = connectionName_;

    ResultCode registerResult = RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_,
        endPointName_, connectionCallback_);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, GENERAL_ERROR);

    std::string srcUdid;
    bool getSrcUdidRet = attr.GetStringValue(Attributes::ATTR_MSG_SRC_UDID, srcUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getSrcUdidRet, GENERAL_ERROR);

    std::vector<uint8_t> scheduleData;
    bool getScheduleDataRet = attr.GetUint8ArrayValue(Attributes::ATTR_SCHEDULE_DATA, scheduleData);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleDataRet, GENERAL_ERROR);

    HdiScheduleInfo scheduleInfo;
    auto hdi = HdiWrapper::GetHdiInstance();
    IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, GENERAL_ERROR);

    int32_t ret = hdi->GetLocalScheduleFromMessage(srcUdid, scheduleData, scheduleInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == SUCCESS, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleInfo.executorIndexes.size() == 1, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleInfo.executorMessages.size() == 1, GENERAL_ERROR);

    executorIndex_ = scheduleInfo.executorIndexes[0];
    std::weak_ptr<ResourceNode> weakNode = ResourceNodePool::Instance().Select(executorIndex_);
    std::shared_ptr<ResourceNode> node = weakNode.lock();
    IF_FALSE_LOGE_AND_RETURN_VAL(node != nullptr, GENERAL_ERROR);

    remoteScheduleNode_ = Common::MakeShared<RemoteExecutorStubScheduleNode>(scheduleInfo, weak_from_this(), node);
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteScheduleNode_ != nullptr, GENERAL_ERROR);

    bool startScheduleRet = remoteScheduleNode_->StartSchedule();
    IF_FALSE_LOGE_AND_RETURN_VAL(startScheduleRet, GENERAL_ERROR);

    auto context = ContextFactory::CreateScheduleHolderContext(remoteScheduleNode_);
    IF_FALSE_LOGE_AND_RETURN_VAL(context != nullptr, GENERAL_ERROR);

    bool addContextRet = ContextPool::Instance().Insert(context);
    IF_FALSE_LOGE_AND_RETURN_VAL(addContextRet, GENERAL_ERROR);
    contextId_ = context->GetContextId();

    bool setExtraInfo = attr.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, scheduleInfo.executorMessages[0]);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExtraInfo, GENERAL_ERROR);

    std::vector<uint8_t> publicKey;
    ret = node->BeginExecute(scheduleInfo.scheduleId, publicKey, attr);

    IAM_LOGI("ConnectionName %{public}s scheduleId %{public}s begin execute ret %{public}d", connectionName_.c_str(),
        GET_MASKED_STRING(trace.scheduleId).c_str(), ret);
    return ret;
}

void RemoteExecutorStub::OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");
    IF_FALSE_LOGE_AND_RETURN(request != nullptr);
    IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

    int32_t msgType;
    bool getMsgTypeRet = request->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType);
    IF_FALSE_LOGE_AND_RETURN(getMsgTypeRet);

    int32_t resultCode = ResultCode::GENERAL_ERROR;
    switch (msgType) {
        case MessageType::SEND_DATA_TO_EXECUTOR:
            resultCode = ProcSendDataMsg(*request);
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

int32_t RemoteExecutorStub::OnMessage(ExecutorRole dstRole, const std::vector<uint8_t> &msg)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteScheduleNode_ != nullptr, GENERAL_ERROR);

    IAM_LOGI("start, scheduleId %{public}s", GET_MASKED_STRING(remoteScheduleNode_->GetScheduleId()).c_str());

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(msg);
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::EXECUTOR_SEND_DATA);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, GENERAL_ERROR);

    bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, remoteScheduleNode_->GetScheduleId());
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleIdRet, GENERAL_ERROR);

    bool setDestRoleRet = request->SetInt32Value(Attributes::ATTR_DEST_ROLE, dstRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(setDestRoleRet, GENERAL_ERROR);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        EXECUTOR_PROXY_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("success, ConnectionName %{public}s scheduleId %{public}s", connectionName_.c_str(),
        GET_MASKED_STRING(remoteScheduleNode_->GetScheduleId()).c_str());
    return SUCCESS;
}

int32_t RemoteExecutorStub::ContinueSchedule(ResultCode resultCode, const std::shared_ptr<Attributes> &finalResult)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    IF_FALSE_LOGE_AND_RETURN_VAL(finalResult != nullptr, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteScheduleNode_ != nullptr, GENERAL_ERROR);
    IAM_LOGI("ConnectionName %{public}s scheduleId %{public}s continue schedule", connectionName_.c_str(),
        GET_MASKED_STRING(remoteScheduleNode_->GetScheduleId()).c_str());

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>(finalResult->Serialize());
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, GENERAL_ERROR);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, MessageType::EXECUTOR_FINISH);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, GENERAL_ERROR);

    bool setScheduleIdRet = request->SetUint64Value(Attributes::ATTR_SCHEDULE_ID, remoteScheduleNode_->GetScheduleId());
    IF_FALSE_LOGE_AND_RETURN_VAL(setScheduleIdRet, GENERAL_ERROR);

    bool setResultCodeRet = request->SetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(setResultCodeRet, GENERAL_ERROR);

    MsgCallback msgCallback = [](const std::shared_ptr<Attributes> &) { IAM_LOGI("message sent"); };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        EXECUTOR_PROXY_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("ConnectionName %{public}s scheduleId %{public}s continue schedule "
             "success",
        connectionName_.c_str(), GET_MASKED_STRING(remoteScheduleNode_->GetScheduleId()).c_str());
    return SUCCESS;
}

int32_t RemoteExecutorStub::ProcSendDataMsg(Attributes &attr)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("start");

    uint64_t scheduleId;
    bool getScheduleIdRet = attr.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, scheduleId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getScheduleIdRet, GENERAL_ERROR);
    IAM_LOGI("ConnectionName %{public}s scheduleId %{public}s proc send data", connectionName_.c_str(),
        GET_MASKED_STRING(scheduleId).c_str());

    std::weak_ptr<ResourceNode> weakNode = ResourceNodePool::Instance().Select(executorIndex_);
    std::shared_ptr<ResourceNode> node = weakNode.lock();
    IF_FALSE_LOGE_AND_RETURN_VAL(node != nullptr, GENERAL_ERROR);

    int32_t ret = node->SendData(scheduleId, attr);
    IF_FALSE_LOGE_AND_RETURN_VAL(ret == ResultCode::SUCCESS, GENERAL_ERROR);

    IAM_LOGI("ConnectionName %{public}s scheduleId %{public}s proc send data success", connectionName_.c_str(),
        GET_MASKED_STRING(scheduleId).c_str());
    return ret;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS