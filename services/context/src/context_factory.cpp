/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "context_factory.h"

#include "context_callback_impl.h"
#include "context_pool.h"
#include "delete_context.h"
#include "enroll_context.h"
#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "identify_context.h"
#include "simple_auth_context.h"
#include "schedule_holder_context.h"
#include "widget_context.h"
#include "remote_msg_util.h"

#define LOG_FILE_ID LOG_FILE_CONTEXT_FACTORY
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::shared_ptr<Context> ContextFactory::CreateSimpleAuthContext(const Authentication::AuthenticationPara &para,
    const std::shared_ptr<ContextCallback> &callback, bool needSubscribeAppState)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto auth = Common::MakeShared<AuthenticationImpl>(newContextId, para);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth != nullptr, nullptr);
    auth->SetChallenge(para.challenge);
    auth->SetAccessTokenId(para.tokenId);
    auth->SetEndAfterFirstFail(para.endAfterFirstFail);
    return Common::MakeShared<SimpleAuthContext>(newContextId, auth, callback, needSubscribeAppState);
}

std::shared_ptr<Context> ContextFactory::CreateIdentifyContext(const Identification::IdentificationPara &para,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto identify = Common::MakeShared<IdentificationImpl>(newContextId, para.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(identify != nullptr, nullptr);
    identify->SetChallenge(para.challenge);
    identify->SetAccessTokenId(para.tokenId);
    return Common::MakeShared<IdentifyContext>(newContextId, identify, callback);
}

std::shared_ptr<Context> ContextFactory::CreateEnrollContext(const Enrollment::EnrollmentPara &para,
    const std::shared_ptr<ContextCallback> &callback, bool needSubscribeAppState)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto enroll = Common::MakeShared<EnrollmentImpl>(para);
    IF_FALSE_LOGE_AND_RETURN_VAL(enroll != nullptr, nullptr);
    enroll->SetAuthToken(para.token);
    enroll->SetAccessTokenId(para.tokenId);
    enroll->SetPinSubType(para.pinType);
    enroll->SetIsUpdate(para.isUpdate);
    return Common::MakeShared<EnrollContext>(newContextId, enroll, callback, needSubscribeAppState);
}

std::shared_ptr<Context> ContextFactory::CreateWidgetAuthContext(std::shared_ptr<ContextCallback> callback)
{
    return nullptr;
}

std::shared_ptr<Context> ContextFactory::CreateWidgetContext(const AuthWidgetContextPara &para,
    std::shared_ptr<ContextCallback> callback, const sptr<IModalCallback> &modalCallback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    return Common::MakeShared<WidgetContext>(newContextId, para, callback, modalCallback);
}

std::shared_ptr<Context> ContextFactory::CreateRemoteAuthContext(const Authentication::AuthenticationPara &para,
    RemoteAuthContextParam &remoteAuthContextParam, const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);

    uint64_t newContextId = ContextPool::GetNewContextId();
    auto auth = Common::MakeShared<AuthenticationImpl>(newContextId, para);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth != nullptr, nullptr);
    auth->SetChallenge(para.challenge);
    auth->SetAccessTokenId(para.tokenId);

    if (remoteAuthContextParam.connectionName == "") {
        bool getConnectionNameRet = RemoteMsgUtil::GetConnectionName(newContextId,
            remoteAuthContextParam.connectionName);
        IF_FALSE_LOGE_AND_RETURN_VAL(getConnectionNameRet, nullptr);
    }

    return Common::MakeShared<RemoteAuthContext>(newContextId, auth, remoteAuthContextParam, callback);
}

std::shared_ptr<Context> ContextFactory::CreateRemoteAuthInvokerContext(AuthParamInner authParam,
    RemoteAuthInvokerContextParam param, std::shared_ptr<ContextCallback> callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);

    uint64_t newContextId = ContextPool::GetNewContextId();
    bool getConnectionNameRet = RemoteMsgUtil::GetConnectionName(newContextId, param.connectionName);
    IF_FALSE_LOGE_AND_RETURN_VAL(getConnectionNameRet, nullptr);

    return Common::MakeShared<RemoteAuthInvokerContext>(newContextId, authParam, param, callback);
}

std::shared_ptr<Context> ContextFactory::CreateLocalRemoteAuthContext(const Authentication::AuthenticationPara &para,
    LocalRemoteAuthContextParam &localRemoteAuthContextParam, const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);

    uint64_t newContextId = ContextPool::GetNewContextId();
    auto auth = Common::MakeShared<AuthenticationImpl>(newContextId, para);
    IF_FALSE_LOGE_AND_RETURN_VAL(auth != nullptr, nullptr);
    auth->SetChallenge(para.challenge);
    auth->SetAccessTokenId(para.tokenId);
    return Common::MakeShared<LocalRemoteAuthContext>(newContextId, auth, localRemoteAuthContextParam, callback);
}

std::shared_ptr<Context> ContextFactory::CreateScheduleHolderContext(std::shared_ptr<ScheduleNode> scheduleNode)
{
    uint64_t newContextId = ContextPool::GetNewContextId();
    return Common::MakeShared<ScheduleHolderContext>(newContextId, scheduleNode);
}

std::shared_ptr<Context> ContextFactory::CreateDeleteContext(const Deletion::DeleteParam &para,
    const std::shared_ptr<ContextCallback> &callback)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, nullptr);
    uint64_t newContextId = ContextPool::GetNewContextId();
    auto deleteImpl = Common::MakeShared<DeleteImpl>(para);
    IF_FALSE_LOGE_AND_RETURN_VAL(deleteImpl != nullptr, nullptr);
    deleteImpl->SetAccessTokenId(para.tokenId);
    return Common::MakeShared<DeleteContext>(newContextId, deleteImpl, callback);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
