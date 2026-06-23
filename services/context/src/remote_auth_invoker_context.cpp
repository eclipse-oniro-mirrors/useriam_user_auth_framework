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

#include "remote_auth_invoker_context.h"

#include <sstream>

#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "relative_timer.h"
#include "remote_connect_manager.h"
#include "thread_handler.h"
#include "thread_handler_manager.h"
#include "user_auth_hdi.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_REMOTE_AUTH_INVOKER_CONTEXT

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t TIME_OUT_MS = 3 * 60 * 1000; // 3min
}
class RemoteAuthInvokerContextMessageCallback : public ConnectionListener, public NoCopyable {
public:
    explicit RemoteAuthInvokerContextMessageCallback(std::weak_ptr<BaseContext> callbackWeakBase,
        RemoteAuthInvokerContext *callback)
        : callbackWeakBase_(callbackWeakBase),
          callback_(callback),
          threadHandler_(ThreadHandler::GetSingleThreadInstance())
    {
    }

    ~RemoteAuthInvokerContextMessageCallback() = default;

    void OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
        const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply) override
    {
        IF_FALSE_LOGE_AND_RETURN(request != nullptr);
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        IAM_LOGI("connectionName: %{public}s, srcEndPoint: %{public}s", connectionName.c_str(), srcEndPoint.c_str());

        std::shared_ptr<BaseContext> callbackSharedBase = callbackWeakBase_.lock();
        IF_FALSE_LOGE_AND_RETURN(callbackSharedBase != nullptr);

        IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);
        callback_->OnMessage(connectionName, srcEndPoint, request, reply);
    }

    void OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus) override
    {
        IAM_LOGI("connectionName: %{public}s, connectStatus %{public}d", connectionName.c_str(), connectStatus);

        IF_FALSE_LOGE_AND_RETURN(threadHandler_ != nullptr);
        threadHandler_->PostTask(
            [connectionName, connectStatus, callbackWeakBase = callbackWeakBase_, callback = callback_, this]() {
                IAM_LOGI("OnConnectStatus process begin");
                auto callbackSharedBase = callbackWeakBase.lock();
                IF_FALSE_LOGE_AND_RETURN(callbackSharedBase != nullptr);

                IF_FALSE_LOGE_AND_RETURN(callback != nullptr);
                callback->OnConnectStatus(connectionName, connectStatus);
                IAM_LOGI("OnConnectStatus process success");
            });
        IAM_LOGI("task posted");
    }

private:
    std::weak_ptr<BaseContext> callbackWeakBase_;
    RemoteAuthInvokerContext *callback_;
    std::shared_ptr<ThreadHandler> threadHandler_ = nullptr;
};

RemoteAuthInvokerContext::RemoteAuthInvokerContext(uint64_t contextId, AuthParamInner authParam,
    RemoteAuthInvokerContextParam param, std::shared_ptr<ContextCallback> callback)
    : BaseContext("RemoteAuthInvokerContext", contextId, callback, true),
      authParam_(authParam),
      connectionName_(param.connectionName),
      verifierNetworkId_(param.verifierNetworkId),
      collectorNetworkId_(param.collectorNetworkId),
      tokenId_(param.tokenId),
      collectorTokenId_(param.collectorTokenId),
      callerName_(param.callerName),
      callerType_(param.callerType),
      callback_(callback)
{
    endPointName_ = REMOTE_AUTH_INVOKER_CONTEXT_ENDPOINT_NAME;
    ThreadHandlerManager::GetInstance().CreateThreadHandler(connectionName_);
}

RemoteAuthInvokerContext::~RemoteAuthInvokerContext()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (cancelTimerId_.has_value()) {
        RelativeTimer::GetInstance().Unregister(cancelTimerId_.value());
    }
    RemoteConnectionManager::GetInstance().UnregisterConnectionListener(connectionName_, endPointName_);
    RemoteConnectionManager::GetInstance().CloseConnection(connectionName_);
    ThreadHandlerManager::GetInstance().DestroyThreadHandler(connectionName_);
    IAM_LOGI("%{public}s destroy", GetDescription());
}

ContextType RemoteAuthInvokerContext::GetContextType() const
{
    return ContextType::REMOTE_AUTH_INVOKER_CONTEXT;
}

uint32_t RemoteAuthInvokerContext::GetTokenId() const
{
    return tokenId_;
}

void RemoteAuthInvokerContext::OnMessage(const std::string &connectionName, const std::string &srcEndPoint,
    const std::shared_ptr<Attributes> &request, std::shared_ptr<Attributes> &reply)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

    int32_t msgType;
    IF_FALSE_LOGE_AND_RETURN(request->GetInt32Value(Attributes::ATTR_MSG_TYPE, msgType));

    int32_t resultCode = ResultCode::GENERAL_ERROR;
    switch (msgType) {
        case SEND_REMOTE_AUTH_TIP:
            resultCode = ProcAuthTipMsg(*request);
            break;
        case SEND_REMOTE_AUTH_RESULT:
            resultCode = ProcAuthResultMsg(*request);
            break;
        default:
            IAM_LOGE("%{public}s invalid msgType:%{public}d", GetDescription(), msgType);
            break;
    }

    IF_FALSE_LOGE_AND_RETURN(resultCode == ResultCode::SUCCESS);
    IF_FALSE_LOGE_AND_RETURN(reply != nullptr);
    bool setResultCodeRet = reply->SetInt32Value(Attributes::ATTR_RESULT_CODE, ResultCode::SUCCESS);
    IF_FALSE_LOGE_AND_RETURN(setResultCodeRet);
}

void RemoteAuthInvokerContext::OnConnectStatus(const std::string &connectionName, ConnectStatus connectStatus)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    if (connectStatus == ConnectStatus::DISCONNECTED) {
        IAM_LOGI("%{public}s connection is disconnected", GetDescription());
        callback_->SetTraceAuthFinishReason("RemoteAuthInvokerContext OnConnectStatus disconnected");
        callback_->OnResult(REMOTE_DEVICE_CONNECTION_FAIL, attr);
        return;
    } else {
        IAM_LOGI("%{public}s connection is connected", GetDescription());
        bool sendRequestRet = SendRequest();
        if (!sendRequestRet) {
            std::stringstream ss;
            ss << "RemoteAuthInvokerContext OnConnectStatus send message fail " << GetLatestError();
            IAM_LOGE("%{public}s %{public}s", GetDescription(), ss.str().c_str());
            callback_->SetTraceAuthFinishReason(ss.str());
            callback_->OnResult(GetLatestError(), attr);
            return;
        }
        IAM_LOGI("%{public}s connection is connected processed", GetDescription());
    }
}

void RemoteAuthInvokerContext::SetVerifierContextId(uint64_t contextId)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    verifierContextId_ = contextId;
    IAM_LOGI("%{public}s set verifierContextId %{public}s success", GetDescription(),
        GET_MASKED_STRING(contextId).c_str());
}

bool RemoteAuthInvokerContext::OnStart()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    cancelTimerId_ = RelativeTimer::GetInstance().Register(
        [weakThis = weak_from_this(), this]() {
            auto sharedThis = weakThis.lock();
            IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);
            OnTimeOut();
        },
        TIME_OUT_MS);

    bool getUdidRet = DeviceManagerUtil::GetInstance().GetUdidByNetworkId(verifierNetworkId_, verifierUdid_);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUdidRet, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback_ != nullptr, false);
    callback_->SetTraceIsRemoteAuth(true);
    callback_->SetTraceRemoteUdid(verifierUdid_);
    callback_->SetTraceConnectionName(connectionName_);
    std::string localUdid;
    IF_FALSE_LOGE_AND_RETURN_VAL(DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(localUdid), false);
    callback_->SetTraceLocalUdid(localUdid);
    endPointName_ = REMOTE_AUTH_INVOKER_CONTEXT_ENDPOINT_NAME;

    std::shared_ptr<RemoteAuthInvokerContextMessageCallback> callback =
        Common::MakeShared<RemoteAuthInvokerContextMessageCallback>(shared_from_this(), this);
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, false);

    ResultCode registerResult =
        RemoteConnectionManager::GetInstance().RegisterConnectionListener(connectionName_, endPointName_, callback);
    IF_FALSE_LOGE_AND_RETURN_VAL(registerResult == SUCCESS, false);

    ResultCode connectResult =
        RemoteConnectionManager::GetInstance().OpenConnection(connectionName_, verifierNetworkId_, GetTokenId());
    if (connectResult != SUCCESS) {
        IAM_LOGE("%{public}s open connection fail %{public}d", GetDescription(), connectResult);
        SetLatestError(REMOTE_DEVICE_CONNECTION_FAIL);
        return false;
    }

    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

bool RemoteAuthInvokerContext::SendRequest()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    request_ = Common::MakeShared<Attributes>();
    IF_FALSE_LOGE_AND_RETURN_VAL(request_ != nullptr, false);

    std::vector<int32_t> authTypes = { static_cast<int32_t>(authParam_.authType) };
    ResultCode getExecutorInfoRet = RemoteMsgUtil::GetQueryExecutorInfoReply(authTypes, COLLECTOR, verifierUdid_,
        *request_);
    if (getExecutorInfoRet != SUCCESS) {
        IAM_LOGE("%{public}s get executor info failed, ret: %{public}d", GetDescription(), getExecutorInfoRet);
        SetLatestError(getExecutorInfoRet);
        return false;
    }

    bool setMsgTypeRet = request_->SetInt32Value(Attributes::ATTR_MSG_TYPE, START_REMOTE_AUTH);
    bool encodeAuthParamRet = RemoteMsgUtil::EncodeAuthParam(authParam_, *request_);
    bool setTokenIdRet = request_->SetUint32Value(Attributes::ATTR_COLLECTOR_TOKEN_ID, collectorTokenId_);
    bool setCallerNameRet = request_->SetStringValue(Attributes::ATTR_CALLER_NAME, callerName_);
    bool setCallerTypeRet = request_->SetInt32Value(Attributes::ATTR_CALLER_TYPE, callerType_);
    bool setNetworkIdRet = request_->SetStringValue(Attributes::ATTR_COLLECTOR_NETWORK_ID, collectorNetworkId_);
    IF_FALSE_LOGE_AND_RETURN_VAL(setMsgTypeRet && encodeAuthParamRet && setTokenIdRet && setCallerNameRet &&
        setCallerTypeRet && setNetworkIdRet, false);

    MsgCallback msgCallback = [weakThis = weak_from_this(), this](const std::shared_ptr<Attributes> &reply) {
        IF_FALSE_LOGE_AND_RETURN(reply != nullptr);

        auto sharedThis = weakThis.lock();
        IF_FALSE_LOGE_AND_RETURN(sharedThis != nullptr);

        int32_t resultCode;
        bool getResultCodeRet = reply->GetInt32Value(Attributes::ATTR_RESULT_CODE, resultCode);
        IF_FALSE_LOGE_AND_RETURN(getResultCodeRet);

        if (resultCode != ResultCode::SUCCESS) {
            IAM_LOGE("%{public}s start remote auth failed %{public}d", GetDescription(), resultCode);
            Attributes attr;
            callback_->SetTraceAuthFinishReason("RemoteAuthInvokerContext START_REMOTE_AUTH fail");
            callback_->OnResult(resultCode, attr);
            return;
        }

        uint64_t contextId;
        bool getContextIdRet = reply->GetUint64Value(Attributes::ATTR_CONTEXT_ID, contextId);
        IF_FALSE_LOGE_AND_RETURN(getContextIdRet);

        this->SetVerifierContextId(contextId);
        IAM_LOGI("%{public}s start remote auth success %{public}d", GetDescription(), resultCode);
    };
    IF_FALSE_LOGE_AND_RETURN_VAL(request_ != nullptr, false);
    ResultCode sendMsgRet = RemoteConnectionManager::GetInstance().SendMessage(connectionName_, endPointName_,
        REMOTE_SERVICE_ENDPOINT_NAME, request_, msgCallback);
    IF_FALSE_LOGE_AND_RETURN_VAL(sendMsgRet == SUCCESS, false);

    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

void RemoteAuthInvokerContext::OnResult(int32_t resultCode, const std::shared_ptr<Attributes> &scheduleResultAttr)
{
    IAM_LOGE("%{public}s this method is not supported", GetDescription());
}

bool RemoteAuthInvokerContext::OnStop()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s canceled", GetDescription());
    Attributes attr;
    IF_FALSE_LOGE_AND_RETURN_VAL(callback_ != nullptr, false);
    callback_->SetTraceAuthFinishReason("RemoteAuthInvokerContext OnStop");
    callback_->OnResult(ResultCode::CANCELED, attr);
    // other module is canceled by disconnecting the connection

    IAM_LOGI("%{public}s success", GetDescription());
    return true;
}

int32_t RemoteAuthInvokerContext::ProcAuthTipMsg(Attributes &message)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    int32_t destRole;
    bool getDestRoleRet = message.GetInt32Value(Attributes::ATTR_DEST_ROLE, destRole);
    IF_FALSE_LOGE_AND_RETURN_VAL(getDestRoleRet, ResultCode::GENERAL_ERROR);

    int32_t tipInfo;
    bool getAcquireInfoRet = message.GetInt32Value(Attributes::ATTR_TIP_INFO, tipInfo);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAcquireInfoRet, ResultCode::GENERAL_ERROR);

    IF_FALSE_LOGE_AND_RETURN_VAL(callback_ != nullptr, ResultCode::GENERAL_ERROR);
    callback_->OnAcquireInfo(static_cast<ExecutorRole>(destRole), tipInfo, message.Serialize());

    IAM_LOGI("%{public}s success", GetDescription());
    return ResultCode::SUCCESS;
}

int32_t RemoteAuthInvokerContext::ProcAuthResultMsgInner(Attributes &message, int32_t &resultCode, Attributes &attr)
{
    resultCode = GENERAL_ERROR;
    bool getResultCodeRet = message.GetInt32Value(Attributes::ATTR_RESULT, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(getResultCodeRet, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> remoteAuthResult;
    bool getRemoteAuthResultRet = message.GetUint8ArrayValue(Attributes::ATTR_SIGNED_AUTH_RESULT, remoteAuthResult);
    if (getRemoteAuthResultRet) {
        auto hdi = HdiWrapper::GetHdiInstance();
        IF_FALSE_LOGE_AND_RETURN_VAL(hdi != nullptr, ResultCode::GENERAL_ERROR);
        HdiAuthResultInfo authResultInfo;
        int32_t hdiRet = hdi->GetAuthResultFromMessage(verifierUdid_, remoteAuthResult, authResultInfo);
        IF_FALSE_LOGE_AND_RETURN_VAL(hdiRet == SUCCESS, ResultCode::GENERAL_ERROR);

        resultCode = authResultInfo.result;
        if (resultCode == ResultCode::FAIL || resultCode == ResultCode::LOCKED || resultCode == ResultCode::SUCCESS) {
            bool setLockOutDurationRet =
                attr.SetInt32Value(Attributes::ATTR_LOCKOUT_DURATION, authResultInfo.lockoutDuration);
            IF_FALSE_LOGE_AND_RETURN_VAL(setLockOutDurationRet, ResultCode::GENERAL_ERROR);
            bool setRemainAttemptsRet =
                attr.SetInt32Value(Attributes::ATTR_REMAIN_ATTEMPTS, authResultInfo.remainAttempts);
            IF_FALSE_LOGE_AND_RETURN_VAL(setRemainAttemptsRet, ResultCode::GENERAL_ERROR);
        }
        if (resultCode == ResultCode::SUCCESS) {
            bool setTokenRet = attr.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authResultInfo.token);
            IF_FALSE_LOGE_AND_RETURN_VAL(setTokenRet, ResultCode::GENERAL_ERROR);
            bool setTokenFromRemoteDevice = attr.SetBoolValue(Attributes::ATTR_TOKEN_FROM_REMOTE_DEVICE, true);
            IF_FALSE_LOGE_AND_RETURN_VAL(setTokenFromRemoteDevice, ResultCode::GENERAL_ERROR);
            bool setUserId = attr.SetInt32Value(Attributes::ATTR_USER_ID, authResultInfo.userId);
            IF_FALSE_LOGE_AND_RETURN_VAL(setUserId, ResultCode::GENERAL_ERROR);
        }
        HILOG_COMM_INFO("%{public}s parsed auth result: %{public}d, lockout duration %{public}d, "
                 "remain attempts %{public}d, token size %{public}zu, user id %{public}d",
            GetDescription(), resultCode, authResultInfo.lockoutDuration, authResultInfo.remainAttempts,
            authResultInfo.token.size(), authResultInfo.userId);
    } else if (resultCode == ResultCode::SUCCESS) {
        IAM_LOGE("%{public}s remote auth result is empty, set result GENERAL_ERROR", GetDescription());
        resultCode = ResultCode::GENERAL_ERROR;
    }

    IAM_LOGI("%{public}s result code %{public}d", GetDescription(), resultCode);
    bool setResultCodeRet = attr.SetInt32Value(Attributes::ATTR_RESULT, resultCode);
    IF_FALSE_LOGE_AND_RETURN_VAL(setResultCodeRet, ResultCode::GENERAL_ERROR);

    return ResultCode::SUCCESS;
}

int32_t RemoteAuthInvokerContext::ProcAuthResultMsg(Attributes &message)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IAM_LOGI("%{public}s start", GetDescription());

    int32_t authResultCode = GENERAL_ERROR;
    Attributes attr;

    int32_t ret = ProcAuthResultMsgInner(message, authResultCode, attr);

    callback_->SetTraceAuthFinishReason("RemoteAuthInvokerContext ProcAuthResultMsg");
    callback_->OnResult(authResultCode, attr);

    IAM_LOGI("%{public}s success", GetDescription());
    return ret;
}

void RemoteAuthInvokerContext::OnTimeOut()
{
    IAM_LOGI("%{public}s timeout", GetDescription());
    IF_FALSE_LOGE_AND_RETURN(callback_ != nullptr);

    Attributes attr;
    callback_->SetTraceAuthFinishReason("RemoteAuthInvokerContext OnTimeOut");
    callback_->OnResult(TIMEOUT, attr);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS