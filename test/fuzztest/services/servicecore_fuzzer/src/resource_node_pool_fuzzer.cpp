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

#include "resource_node_pool_fuzzer.h"

#include "common_dummy.h"
#include "resource_node_pool.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#undef LOG_FILE_ID
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_POOL_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
void FuzzResourcePoolInsert(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    auto node = Common::MakeShared<DummyResourceNode>();
    ResourceNodePool::Instance().Insert(node);
    IAM_LOGI("end");
}

void FuzzResourcePoolDelete(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    ResourceNodePool::Instance().Delete(executorIndex);
    IAM_LOGI("end");
}

void FuzzResourcePoolDeleteAll(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    ResourceNodePool::Instance().DeleteAll();
    IAM_LOGI("end");
}

void FuzzResourcePoolSelect(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    ResourceNodePool::Instance().Select(executorIndex);
    IAM_LOGI("end");
}

void FuzzResourcePoolGetPoolSize(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    ResourceNodePool::Instance().GetPoolSize();
    IAM_LOGI("end");
}

void FuzzRegisterResourceNodePoolListener(Parcel &parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyResourceNodePoolListener>();
    ResourceNodePool::Instance().RegisterResourceNodePoolListener(listener);
    IAM_LOGI("end");
}

void FuzzDeregisterResourceNodePoolListener(Parcel &parcel)
{
    IAM_LOGI("start");
    auto listener = Common::MakeShared<DummyResourceNodePoolListener>();
    ResourceNodePool::Instance().DeregisterResourceNodePoolListener(listener);
    IAM_LOGI("end");
}

using ResourcePoolFuzzFunc = decltype(FuzzResourcePoolInsert);
ResourcePoolFuzzFunc *g_ResourcePoolFuzzFuncs[] = {
    FuzzResourcePoolInsert,
    FuzzResourcePoolDelete,
    FuzzResourcePoolDeleteAll,
    FuzzResourcePoolSelect,
    FuzzResourcePoolGetPoolSize,
    FuzzRegisterResourceNodePoolListener,
    FuzzDeregisterResourceNodePoolListener,
};
} // namespace

void ResourceNodePoolFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_ResourcePoolFuzzFuncs) / sizeof(ResourcePoolFuzzFunc *));
    auto fuzzFunc = g_ResourcePoolFuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
