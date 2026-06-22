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

#include "risk_event_manager_fuzzer.h"

#include "os_accounts_manager.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "risk_event_manager.h"
#include "screenlock_status_listener.h"
#include "strong_auth_status_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RISK_EVENT_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
void FuzzRiskEventManagerMain(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    Attributes attributes;
    std::vector<uint8_t> extraInfo;
    RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(mainUserId,
        AuthType::FACE, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH);
    RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(inValidUserId,
        AuthType::FACE, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH);
    RiskEventManager::GetInstance().SetRiskEventPropertyForAuthType(mainUserId,
        AuthType::PIN, RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH);
    RiskEventManager::GetInstance().SetAttributes(mainUserId, AuthType::FACE,
        RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH, attributes);
    RiskEventManager::GetInstance().SetAttributes(inValidUserId, AuthType::FACE,
        RiskEventManager::EventType::SCREENLOCK_STRONG_AUTH, attributes);
    RiskEventManager::GetInstance().SetAttributes(mainUserId, AuthType::FACE,
        RiskEventManager::EventType::UNKNOWN, attributes);
    RiskEventManager::GetInstance().GetStrongAuthExtraInfo(mainUserId,
        AuthType::FACE, extraInfo);
    IAM_LOGI("end");
}

void FuzzGetTemplateIdList(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    std::vector<uint64_t> templateIds;
    RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, AuthType::FACE,
        templateIds);
    RiskEventManager::GetInstance().GetTemplateIdList(inValidUserId, AuthType::FACE,
        templateIds);
    RiskEventManager::GetInstance().GetTemplateIdList(mainUserId, AuthType::PIN,
        templateIds);
    RiskEventManager::GetInstance().GetTemplateIdList(inValidUserId, AuthType::PIN,
        templateIds);
    IAM_LOGI("end");
}

void FuzzHandleStrongAuthEvent(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    std::vector<int32_t> userIdList;
    RiskEventManager::GetInstance().HandleStrongAuthEvent(mainUserId);
    RiskEventManager::GetInstance().HandleStrongAuthEvent(inValidUserId);
    RiskEventManager::GetInstance().SyncRiskEvents();
    RiskEventManager::GetInstance().OnScreenLock();
    IAM_LOGI("end");
}

void FuzzStrongAuthStatusManager(Parcel &parcel)
{
    IAM_LOGI("begin");
    int32_t mainUserId = 100;
    int32_t inValidUserId = -1;
    StrongAuthStatusManager::Instance().RegisterStrongAuthListener();
    StrongAuthStatusManager::Instance().RegisterStrongAuthListener();
    StrongAuthStatusManager::Instance().SyncStrongAuthStatusForAllAccounts();
    StrongAuthStatusManager::Instance().UnRegisterStrongAuthListener();
    StrongAuthStatusManager::Instance().UnRegisterStrongAuthListener();
    StrongAuthStatusManager::Instance().StartSubscribe();
    StrongAuthStatusManager::Instance().StartSubscribe();
    StrongAuthStatusManager::Instance().IsScreenLockStrongAuth(mainUserId);
    StrongAuthStatusManager::Instance().IsScreenLockStrongAuth(inValidUserId);
    IAM_LOGI("end");
}

void FuzzOsAccountsManager(Parcel &parcel)
{
    IAM_LOGI("begin");
    OsAccountsManager::Instance().StartSubscribe();
    OsAccountsManager::Instance().StartSubscribe();
    OsAccountsManager::Instance().OnOsAccountSaAdd();
    OsAccountsManager::Instance().OnOsAccountSaAdd();
    OsAccountsManager::Instance().OnOsAccountSaRemove();
    OsAccountsManager::Instance().OnOsAccountSaRemove();
    IAM_LOGI("end");
}

using RiskEventManagerFuzzFunc = decltype(FuzzRiskEventManagerMain);
RiskEventManagerFuzzFunc *g_RiskEventManagerFuzzFuncs[] = {
    FuzzRiskEventManagerMain,
    FuzzGetTemplateIdList,
    FuzzHandleStrongAuthEvent,
    FuzzStrongAuthStatusManager,
    FuzzOsAccountsManager,
};
} // namespace

void RiskEventManagerFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_RiskEventManagerFuzzFuncs) / sizeof(RiskEventManagerFuzzFunc *));
    auto fuzzFunc = g_RiskEventManagerFuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
