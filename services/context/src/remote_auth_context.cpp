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

#include "remote_auth_context.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"

#include "device_manager_util.h"
#include "relative_timer.h"
#include "remote_msg_util.h"
#include "resource_node_utils.h"
#include "thread_handler.h"
#include "thread_handler_manager.h"

#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_CONTEXT
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t SETUP_CONNECTION_TIME_OUT_MS = 3 * 60 * 1000; // 3min
}
class RemoteAuthContextMessageCallback : public ConnectionListener, public NoCopyable {
public:
    RemoteAuthContextMessageCallback(std::weak_ptr<BaseContext> callbackWeakBase,
        std::weak_ptr<RemoteAuthContext> callback)
        : callbackWeakBase_(callbackWeakBase),
          callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }

    ~RemoteAuthContextMessageCallback() = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());
    }

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) override
    {
        IAM_LOGI("connectionName: %{public}s, connectStatus %{public}d", connectionName.c_str(), connectStatus);

        IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
        threadHandler_->PostTask(
            [connectionName, connectStatus, callbackWeakBase = callbackWeakBase_, callbackWeak = callback_, this]() {
                IAM_LOGI("OnConnectStatus process begin");
                auto callbackSharedBase = callbackWeakBase.lock();
                IF_FALSE_LOGE_AND_RETURN(callbackSharedBase != nullptr);

                auto callbackShared = callbackWeak.lock();
                IF_FALSE_LOGE_AND_RETURN(callbackShared != nullptr);
                callbackShared->OnConnectStatus(connectionName, connectStatus);
                IAM_LOGI("OnConnectStatus process success");
            });
        IAM_LOGI("task posted");
    }

private:
    std::weak_ptr<BaseContext> callbackWeakBase_;
    std::weak_ptr<RemoteAuthContext> callback_;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteAuthContext::RemoteAuthContext(uint64_t contextId, std::shared_ptr<Authentication> auth,
    RemoteAuthContextParam &param, std::shared_ptr<ContextCallback> callback)
    : SimpleAuthContext("RemoteAuthContext", contextId, auth, callback),
      authType_(param.authType),
      connectionName_(param.connectionName),
      collectorNetworkId_(param.collectorNetworkId),
      executorInfoMsg_(param.executorInfoMsg)
{
    endPointName_ = REMOTE_AUTH_CONTEXT_ENDPOINT_NAME;
    needSetupConnection_ = (executorInfoMsg_.size() == 0);
    if (needSetupConnection_) {
        ThreadHandlerManager::GetInstance().CreateThreadHandler(connectionName_);
    }
}

RemoteAuthContext::~RemoteAuthContext()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (cancelTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(cancelTimerId_.value());
    }
    RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    if (needSetupConnection_) {
        RemoteConnectionManager::GetInstance().CloseConnection(connectionName_);
        ThreadHandlerManager::GetInstance().DestroyThreadHandler(connectionName_);
    }
    IAM_LOGI("%{public}s destroy", GetDescription());
}

ContextType RemoteAuthContext::GetContextType() const
{
    return REMOTE_AUTH_CONTEXT;
}

void RemoteAuthContext::SetExecutorInfoMsg(std::vector<uint8_t> msg)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    executorInfoMsg_ = msg;
    IAM_LOGI("%{public}s executorInfoMsg_ size is %{public}zu", GetDescription(), executorInfoMsg_.size());
}

bool RemoteAuthContext::OnStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    cancelTimerId_ = RelativeTimer::GetInstance().Register(
        [weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            OnTimeOut();
        },
        SETUP_CONNECTION_TIME_OUT_MS);

    if (needSetupConnection_) {
        IAM_LOGI("%{public}s SetupConnection", GetDescription());
        return SetupConnection();
    }

    IAM_LOGI("%{public}s StartAuth", GetDescription());
    return StartAuth();
}

bool RemoteAuthContext::StartAuth()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start remote auth", GetDescription());

    IF_FALSE_LOGE_AND_RETURN_VAL(executorInfoMsg_.size() > 0, false);

    std::vector<ExecutorInfo> executorInfos;
    bool decodeRet = RemoteMsgUtil::DecodeQueryExecutorInfoReply(Attributes(executorInfoMsg_), executorInfos);
    IF_FALSE_LOGE_AND_RETURN_VAL(decodeRet, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(executorInfos.size() > 0, false);

    remoteExecutorProxy_ = Common::MakeShared<RemoteExecutorProxy>(connectionName_, executorInfos[0]);
    IF_FALSE_LOGE_AND_RETURN_VAL(remoteExecutorProxy_ != nullptr, false);

    ResultCode startExecutorRet = remoteExecutorProxy_->Start();
    IF_FALSE_LOGE_AND_RETURN_VAL(startExecutorRet == SUCCESS, false);

    std::string collectorUdid;
    bool getCollectorUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(collectorNetworkId_, collectorUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getCollectorUdidRet, false);

    IF_FALSE_LOGE_AND_RETURN_VAL(callback_ != nullptr, false);
    callback_->SetTraceRemoteUdid(collectorUdid);
    callback_->SetTraceIsRemoteAuth(true);
    std::string localUdid;
    IF_FALSE_LOGE_AND_RETURN_VAL(DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid), false);
    callback_->SetTraceLocalUdid(localUdid);
    callback_->SetTraceConnectionName(connectionName_);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth_ != nullptr, false);
    auth_->SetCollectorUdid(collectorUdid);

    bool startAuthRet = SimpleAuthContext::OnStart();
    IF_FALSE_LOGE_AND_RETURN_VAL(startAuthRet, false);
    auto scheduleList = GetScheduleList();
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList.size() == 1, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(scheduleList[0] != nullptr, false);

    IAM_LOGI("%{public}s start remote auth success, connectionName:%{public}s, scheduleId:%{public}s",
        GetDescription(), connectionName_.c_str(), GET_MASKED_STRING(scheduleList[0]->GetScheduleId()).c_str());
    return true;
}

void RemoteAuthContext::StartAuthDelayed()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
    IAM_LOGI("%{public}s start", GetDescription());

    bool ret = StartAuth();
    if (!ret) {
        IAM_LOGE("%{public}s StartAuth failed, latest error %{public}d", GetDescription(), GetLatestError());
        Attributes attr;
        callback_->SetTraceAuthFinishReason("RemoteAuthContext StartAuthDelayed fail");
        callback_->OnResult(GetLatestError(), attr);
        return;
    }
    IAM_LOGI("%{public}s success", GetDescription());
}

bool RemoteAuthContext::SendQueryExecutorInfoMsg()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    std::shared_ptr<Attributes> request = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN_VAL(request != nullptr, false);

    bool setMsgTypeRet = request->SetInt32Value(Attributes::ATTR_MSG_TYPE, QUERY_EXECUTOR_INFO);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet, false);

    std::vector<int32_t> authTypes = { authType_ };
    bool setAuthTypesRet = request->SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, authTypes);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypesRet, false);

    bool setExecutorRoleRet = request->SetInt32Value(Attributes::ATTR_EXECUTOR_ROLE, COLLECTOR);
    IF_FALSE_LOGE_AND_RETURN_VAL(setExecutorRoleRet, false);

    std::string localUdid;
    bool getLocalUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid);
    IF_FALSE_LOGE_AND_RETURN_VAL(getLocalUdidRet, false);

    MsgCallback msgCallback = [weakThis = weak_from_this(), this](const std::shared_ptr<Attributes> &reply) {
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        auto sharedThis = weakThis.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);

        int32_t resultCode;
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);

        if (resultCode != SUCCESS) {
            std::stringstream ss;
            ss << "RemoteAuthContext SendQueryExecutorInfoMsg QUERY_EXECUTOR_INFO fail " << resultCode;
            IAM_LOGE("%{public}s %{public}s", GetDescription(), ss.str().c_str());
            callback_->SetTraceAuthFinishReason(ss.str());
            Attributes attr;
            callback_->OnResult(resultCode, attr);
            return;
        }

        SetExecutorInfoMsg(reply->Serialize());

        auto handler = ThreadHandler::GetSingleThreadInstance();
        IF_FALSE_LOGE_AND_RETURN(handler != nullptr);
        handler->PostTask([weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            StartAuthDelayed();
        });
        IAM_LOGI("%{public}s query executor info success", GetDescription());
    };

    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_SERVICE_ENDPOINT_NAME, request, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == SUCCESS, false);

    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

bool RemoteAuthContext::SetupConnection()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    std::shared_ptr<RemoteAuthContextMessageCallback> callback =
        Common::MakeShared<RemoteAuthContextMessageCallback>(shared_from_this(),
            std::static_pointer_cast<RemoteAuthContext>(shared_from_this()));
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);

    ResultCode registerResult =
        RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_, endPointName_, callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, false);

    ResultCode connectResult =
        RemoteConnectionManager::GetInstance().OpenConnection(connectionName_, collectorNetworkId_, GetTokenId());
    if (connectResult != SUCCESS) {
        IAM_LOGE("%{public}s open connection fail %{public}d", GetDescription(), connectResult);
        SetLatestError(REMOTE_DEVICE_CONNECTION_FAIL);
        return false;
    }

    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

void RemoteAuthContext::OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    IF_FALSE_LOGE_AND_RETURN(connectionName_ == connectionName);
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    if (connectStatus == ConnectStatus::DISCONNECTED) {
        IAM_LOGI("%{public}s connection is disconnected", GetDescription());
        callback_->SetTraceAuthFinishReason("RemoteAuthContext OnConnectStatus disconnected");
        callback_->OnResult(REMOTE_DEVICE_CONNECTION_FAIL, attr);
        return;
    } else {
        IAM_LOGI("%{public}s connection is connected", GetDescription());
        bool sendMsgRet = SendQueryExecutorInfoMsg();
        if (!sendMsgRet) {
            IAM_LOGE("%{public}s SendQueryExecutorInfoMsg failed", GetDescription());
            callback_->SetTraceAuthFinishReason("RemoteAuthContext OnConnectStatus send message fail");
            callback_->OnResult(GENERAL_ERROR, attr);
            return;
        }
        IAM_LOGI("%{public}s connection is connected processed", GetDescription());
    }
}

void RemoteAuthContext::OnTimeOut()
{
    IAM_LOGI("%{public}s timeout", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    callback_->SetTraceAuthFinishReason("RemoteAuthContext OnTimeOut");
    callback_->OnResult(TIMEOUT, attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
