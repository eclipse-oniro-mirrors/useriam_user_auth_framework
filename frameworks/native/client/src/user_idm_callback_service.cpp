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

#include "user_idm_callback_service.h"

#include "callback_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_FILE_ID LOG_FILE_USER_IDM_CALLBACK_SERVICE
#define LOG_TAG "USER_IDM_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
IdmCallbackService::IdmCallbackService(const std::shared_ptr<UserIdmClientCallback> &impl)
    : idmClientCallback_(impl),
    iamHitraceHelper_(Common::MakeShared<UserIam::UserAuth::IamHitraceHelper>("IDM InnerKit"))
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default result to caller");
            Attributes extraInfo;
            impl->OnResult(GENERAL_ERROR, extraInfo);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmCallbackService::~IdmCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t IdmCallbackService::OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start, result:%{public}d", resultCode);
    iamHitraceHelper_ = nullptr;
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attribute(extraInfo);
    idmClientCallback_->OnResult(resultCode, attribute);
    return SUCCESS;
}

int32_t IdmCallbackService::OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("start, module:%{public}d acquireInfo:%{public}d", module, acquireInfo);
    if (idmClientCallback_ == nullptr) {
        IAM_LOGE("idm client callback is nullptr");
        return GENERAL_ERROR;
    }
    Attributes attribute(extraInfo);
    idmClientCallback_->OnAcquireInfo(module, static_cast<uint32_t>(acquireInfo), attribute);
    return SUCCESS;
}

int32_t IdmCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IdmCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

IdmGetCredInfoCallbackService::IdmGetCredInfoCallbackService(
    const std::shared_ptr<GetCredentialInfoCallback> &impl) : getCredInfoCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default cred info result to caller");
            std::vector<CredentialInfo> infoList;
            impl->OnCredentialInfo(GENERAL_ERROR, infoList);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmGetCredInfoCallbackService::~IdmGetCredInfoCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t IdmGetCredInfoCallbackService::OnCredentialInfos(int32_t resultCode,
    const std::vector<IpcCredentialInfo> &ipcCredInfoList)
{
    IAM_LOGD("start, cred info vector size:%{public}zu", ipcCredInfoList.size());
    if (getCredInfoCallback_ == nullptr) {
        IAM_LOGE("getCredInfoCallback is nullptr");
        return GENERAL_ERROR;
    }

    std::vector<CredentialInfo> credInfoList;
    for (auto &iter : ipcCredInfoList) {
        CredentialInfo credentialInfo;
        credentialInfo.authType = static_cast<AuthType>(iter.authType);
        credentialInfo.pinType = static_cast<PinSubType>(iter.pinType);
        credentialInfo.credentialId = iter.credentialId;
        credentialInfo.templateId = iter.templateId;
        credentialInfo.isAbandoned = iter.isAbandoned;
        credentialInfo.validityPeriod = iter.validityPeriod;
        credInfoList.push_back(credentialInfo);
    }
    getCredInfoCallback_->OnCredentialInfo(resultCode, credInfoList);
    return SUCCESS;
}

int32_t IdmGetCredInfoCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IdmGetCredInfoCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}

IdmGetSecureUserInfoCallbackService::IdmGetSecureUserInfoCallbackService(
    const std::shared_ptr<GetSecUserInfoCallback> &impl) : getSecInfoCallback_(impl)
{
    CallbackManager::CallbackAction action = [impl]() {
        if (impl != nullptr) {
            IAM_LOGI("user idm service death, return default secure info to caller");
            SecUserInfo info = {};
            impl->OnSecUserInfo(GENERAL_ERROR, info);
        }
    };
    CallbackManager::GetInstance().AddCallback(reinterpret_cast<uintptr_t>(this), action);
}

IdmGetSecureUserInfoCallbackService::~IdmGetSecureUserInfoCallbackService()
{
    CallbackManager::GetInstance().RemoveCallback(reinterpret_cast<uintptr_t>(this));
}

int32_t IdmGetSecureUserInfoCallbackService::OnSecureUserInfo(int32_t resultCode, const IpcSecUserInfo &ipcSecUserInfo)
{
    IAM_LOGI("start, enrolled info vector size:%{public}zu", ipcSecUserInfo.enrolledInfo.size());
    if (getSecInfoCallback_ == nullptr) {
        IAM_LOGE("getSecInfoCallback_ is nullptr");
        return GENERAL_ERROR;
    }

    SecUserInfo secUserInfo = {};
    secUserInfo.secureUid = ipcSecUserInfo.secureUid;
    for (auto &iter : ipcSecUserInfo.enrolledInfo) {
        EnrolledInfo enrolledInfo;
        enrolledInfo.authType = static_cast<AuthType>(iter.authType);
        enrolledInfo.enrolledId = iter.enrolledId;
        secUserInfo.enrolledInfo.push_back(enrolledInfo);
    }
    getSecInfoCallback_->OnSecUserInfo(resultCode, secUserInfo);
    return SUCCESS;
}

int32_t IdmGetSecureUserInfoCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IdmGetSecureUserInfoCallbackService::CallbackExit([[maybe_unused]] uint32_t code,
    [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS