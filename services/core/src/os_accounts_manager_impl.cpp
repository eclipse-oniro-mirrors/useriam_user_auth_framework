/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "os_accounts_manager.h"

#include <singleton.h>

#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "context_pool.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "system_ability_listener.h"
#include "template_cache_manager.h"
#include "thread_handler.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_OS_ACCOUNTS_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
using OsAccountSubscriber = AccountSA::OsAccountSubscriber;
using OsAccountSubscribeInfo = AccountSA::OsAccountSubscribeInfo;
using OS_ACCOUNT_SUBSCRIBE_TYPE = AccountSA::OS_ACCOUNT_SUBSCRIBE_TYPE;
void HandleAccountsChanged(const int id)
{
    auto threadHandler = ThreadHandler::GetSingleThreadInstance();
    IF_FALSE_LOGE_AND_RETURN(threadHandler != nullptr);
    threadHandler->PostTask([id]() {
        TemplateCacheManager::GetInstance().ProcessUserIdChange(id);
    });
}

void SyncOsAccountIdStatus()
{
    IAM_LOGI("start");
    std::optional<int32_t> userIdOpt;
    int32_t ret = IpcCommon::GetActiveUserId(userIdOpt);
    if (ret != SUCCESS || !userIdOpt.has_value()) {
        IAM_LOGE("get current user id fail");
        return;
    }
    int32_t userId = userIdOpt.value();
    if (userId == INVALID_USER_ID) {
        IAM_LOGE("invalid user id");
        return;
    }
    HandleAccountsChanged(userId);
}
}

class UserIamOsAccountSubscriber : public OsAccountSubscriber, public NoCopyable {
public:
    explicit UserIamOsAccountSubscriber(const OsAccountSubscribeInfo &subscribeInfo);
    ~UserIamOsAccountSubscriber() = default;

    void OnAccountsChanged(const int &id) override;
};

class OsAccountsManagerImpl final : public OsAccountsManager, public Singleton<OsAccountsManagerImpl> {
public:
    void StartSubscribe() override;
    void OnOsAccountSaAdd() override;
    void OnOsAccountSaRemove() override;

private:
    sptr<SystemAbilityListener> accountSaStatusListener_ {nullptr};
    std::shared_ptr<UserIamOsAccountSubscriber> subscriber_ {nullptr};
    std::recursive_mutex mutex_;
};

UserIamOsAccountSubscriber::UserIamOsAccountSubscriber(const OsAccountSubscribeInfo &subscribeInfo)
    : OsAccountSubscriber(subscribeInfo)
{
}

void UserIamOsAccountSubscriber::OnAccountsChanged(const int &id)
{
    IAM_LOGI("OnAccountsChanged %{public}d", id);
    HandleAccountsChanged(id);
}

void OsAccountsManagerImpl::StartSubscribe()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (accountSaStatusListener_ != nullptr) {
        return;
    }
    accountSaStatusListener_ = SystemAbilityListener::Subscribe(
        "OsAccountService", SUBSYS_ACCOUNT_SYS_ABILITY_ID_BEGIN,
        []() { OsAccountsManager::Instance().OnOsAccountSaAdd(); },
        []() { OsAccountsManager::Instance().OnOsAccountSaRemove(); });
    IF_FALSE_LOGE_AND_RETURN(accountSaStatusListener_ != nullptr);
}

void OsAccountsManagerImpl::OnOsAccountSaAdd()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (subscriber_ != nullptr) {
        return;
    }
    OsAccountSubscribeInfo subscribeInfo;
    subscribeInfo.SetOsAccountSubscribeType(OS_ACCOUNT_SUBSCRIBE_TYPE::ACTIVATED);
    auto subscriber = Common::MakeShared<UserIamOsAccountSubscriber>(subscribeInfo);
    IF_FALSE_LOGE_AND_RETURN(subscriber != nullptr);

    ErrCode errCode = AccountSA::OsAccountManager::SubscribeOsAccount(subscriber);
    if (errCode != ERR_OK) {
        IAM_LOGE("subscribe fail, errCode = %{public}d", errCode);
        return;
    }
    IF_FALSE_LOGE_AND_RETURN(subscriber != nullptr);
    subscriber_ = subscriber;
    SyncOsAccountIdStatus();
}

void OsAccountsManagerImpl::OnOsAccountSaRemove()
{
    IAM_LOGI("start");
    if (subscriber_ == nullptr) {
        return;
    }

    ErrCode errCode = AccountSA::OsAccountManager::UnsubscribeOsAccount(subscriber_);
    if (errCode != ERR_OK) {
        IAM_LOGE("unsubscribe fail, errCode = %{public}d", errCode);
        return;
    }
    subscriber_ = nullptr;
}

OsAccountsManager &OsAccountsManager::Instance()
{
    return OsAccountsManagerImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS