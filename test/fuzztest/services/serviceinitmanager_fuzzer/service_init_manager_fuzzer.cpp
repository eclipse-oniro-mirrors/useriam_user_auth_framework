/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "service_init_manager_fuzzer.h"

#include <cstdint>

#include "parcel.h"

#include "iam_logger.h"
#include "service_init_manager.h"
#include "thread_handler.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SERVICE_INIT_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
// 从 fuzz 数据直接注入标记状态，驱动 InitGlobalInstance/DeinitGlobalInstance/
// CheckAllFlags/PublishAllServices 分支
void InjectFlags(Parcel &parcel, ServiceInitManager &manager)
{
    manager.isCoAuthServiceStart_ = parcel.ReadBool();
    manager.isUserAuthServiceStart_ = parcel.ReadBool();
    manager.isIdmServiceStart_ = parcel.ReadBool();
    manager.accessTokenReady_ = parcel.ReadBool();
    manager.fwkReady_ = parcel.ReadBool();
    manager.engineReady_ = parcel.ReadBool();
}

// 排空单线程并复位状态，避免跨 fuzz 迭代泄漏
void DrainAndReset(ServiceInitManager &manager)
{
    auto handler = ThreadHandler::GetSingleThreadInstance();
    if (handler != nullptr) {
        handler->EnsureTask([]() {});
    }
    manager.isCoAuthServiceStart_ = false;
    manager.isUserAuthServiceStart_ = false;
    manager.isIdmServiceStart_ = false;
    manager.accessTokenReady_ = false;
    manager.fwkReady_ = false;
    manager.engineReady_ = false;
}

void FuzzCoAuthServiceStart(Parcel &parcel)
{
    IAM_LOGI("FuzzCoAuthServiceStart begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnCoAuthServiceStart();
    DrainAndReset(manager);
    IAM_LOGI("FuzzCoAuthServiceStart end");
}

void FuzzCoAuthServiceStop(Parcel &parcel)
{
    IAM_LOGI("FuzzCoAuthServiceStop begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnCoAuthServiceStop();
    DrainAndReset(manager);
    IAM_LOGI("FuzzCoAuthServiceStop end");
}

void FuzzUserAuthServiceStart(Parcel &parcel)
{
    IAM_LOGI("FuzzUserAuthServiceStart begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnUserAuthServiceStart();
    DrainAndReset(manager);
    IAM_LOGI("FuzzUserAuthServiceStart end");
}

void FuzzUserAuthServiceStop(Parcel &parcel)
{
    IAM_LOGI("FuzzUserAuthServiceStop begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnUserAuthServiceStop();
    DrainAndReset(manager);
    IAM_LOGI("FuzzUserAuthServiceStop end");
}

void FuzzIdmServiceStart(Parcel &parcel)
{
    IAM_LOGI("FuzzIdmServiceStart begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnIdmServiceStart();
    DrainAndReset(manager);
    IAM_LOGI("FuzzIdmServiceStart end");
}

void FuzzIdmServiceStop(Parcel &parcel)
{
    IAM_LOGI("FuzzIdmServiceStop begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnIdmServiceStop();
    DrainAndReset(manager);
    IAM_LOGI("FuzzIdmServiceStop end");
}

void FuzzEngineReady(Parcel &parcel)
{
    IAM_LOGI("FuzzEngineReady begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnEngineReady();
    DrainAndReset(manager);
    IAM_LOGI("FuzzEngineReady end");
}

void FuzzEngineUnavailable(Parcel &parcel)
{
    IAM_LOGI("FuzzEngineUnavailable begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnEngineUnavailable();
    DrainAndReset(manager);
    IAM_LOGI("FuzzEngineUnavailable end");
}

void FuzzAccessTokenReady(Parcel &parcel)
{
    IAM_LOGI("FuzzAccessTokenReady begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.OnAccessTokenReady();
    DrainAndReset(manager);
    IAM_LOGI("FuzzAccessTokenReady end");
}

void FuzzCheckAllFlags(Parcel &parcel)
{
    IAM_LOGI("FuzzCheckAllFlags begin");
    auto &manager = ServiceInitManager::GetInstance();
    InjectFlags(parcel, manager);
    manager.CheckAllFlags();
    DrainAndReset(manager);
    IAM_LOGI("FuzzCheckAllFlags end");
}

using FuzzFunc = decltype(FuzzCoAuthServiceStart);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzCoAuthServiceStart,
    FuzzCoAuthServiceStop,
    FuzzUserAuthServiceStart,
    FuzzUserAuthServiceStop,
    FuzzIdmServiceStart,
    FuzzIdmServiceStop,
    FuzzEngineReady,
    FuzzEngineUnavailable,
    FuzzAccessTokenReady,
    FuzzCheckAllFlags,
};
} // namespace

void ServiceInitManagerFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::ServiceInitManagerFuzzTest(data, size);
    return 0;
}
