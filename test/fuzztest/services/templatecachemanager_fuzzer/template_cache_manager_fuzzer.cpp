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

#include "template_cache_manager_fuzzer.h"

#include <cinttypes>
#include <cstddef>
#include <cstdint>

#include "parcel.h"

#include "iam_common_defines.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "template_cache_manager.h"

#undef private

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_TEMPLATE_CACHE_MANAGER

using namespace std;
using namespace OHOS::UserIam::Common;
using namespace OHOS::UserIam::UserAuth;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

TemplateCacheManager g_templateCacheManger;

void FuzzUpdateTemplateCache(Parcel &parcel)
{
    IAM_LOGI("begin");
    AuthType authType = PIN;
    g_templateCacheManger.UpdateTemplateCache(authType);
    IAM_LOGI("end");
}

void FuzzProcessUserIdChange(Parcel &parcel)
{
    IAM_LOGI("begin");
    int newUserId = 200;
    g_templateCacheManger.ProcessUserIdChange(newUserId);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzUpdateTemplateCache);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzUpdateTemplateCache,
    FuzzProcessUserIdChange,
};

void TemplateCacheManagerFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs)) / sizeof(FuzzFunc *);
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::TemplateCacheManagerFuzzTest(data, size);
    return 0;
}
