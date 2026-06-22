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

#include "context_pool_impl_fuzzer.h"

#include "parcel.h"

#include "dummy_authentication.h"
#include "dummy_context_pool.h"
#include "dummy_iam_callback_interface.h"
#include "dummy_executor_callback_interface.h"
#include "dummy_resource_node.h"
#include "dummy_schedule_node_callback.h"

#include "attributes.h"
#include "context_pool.h"
#include "context_callback_impl.h"
#include "simple_auth_context.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_CONTEXT_POOL_IMPL

#undef private

using namespace std;
using namespace OHOS::UserIam::Common;

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t OPERATION_TYPE = 1;

void FillTest(Parcel &parcel)
{
    IAM_LOGI("begin");
    ContextPool::Instance().GetNewContextId();
    
    auto dummyAuth = MakeShared<DummyAuthentication>();
    auto contextCallback = MakeShared<ContextCallbackImpl>(new (std::nothrow) DummyIamCallbackInterface(),
        static_cast<OperationType>(OPERATION_TYPE));
    auto context = MakeShared<SimpleAuthContext>(parcel.ReadUint64(), dummyAuth, contextCallback, true);

    ContextPool::Instance().Insert(context);

    ContextPool::Instance().Delete(parcel.ReadUint64());

    ContextPool::Instance().CancelAll();

    ContextPool::Instance().Select(parcel.ReadUint64());

    ContextPool::Instance().Select(static_cast<ContextType>(parcel.ReadUint32()));

    ContextPool::Instance().SelectScheduleNodeByScheduleId(parcel.ReadUint64());

    auto listener = MakeShared<DummyContextPool::DummyContextPoolListener>();
    ContextPool::Instance().RegisterContextPoolListener(listener);

    ContextPool::Instance().DeregisterContextPoolListener(listener);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FillTest);
FuzzFunc *g_fuzzFuncs[] = {
    FillTest,
};

void ContextPoolImplFuzzTest(const uint8_t *data, size_t size)
{
    Parcel parcel;
    parcel.WriteBuffer(data, size);
    parcel.RewindRead(0);
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::UserIam::UserAuth::ContextPoolImplFuzzTest(data, size);
    return 0;
}
