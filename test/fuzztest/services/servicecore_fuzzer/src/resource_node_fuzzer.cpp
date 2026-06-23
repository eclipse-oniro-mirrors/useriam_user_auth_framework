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

#include "resource_node_fuzzer.h"

#include "resource_node.h"
#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
class DummyExecutorCallbackInterface final : public IExecutorCallback {
public:
    int32_t OnMessengerReady(const sptr<IExecutorMessenger> &messenger,
        const std::vector<uint8_t> &publicKey, const std::vector<uint64_t> &templateIdList) override
    {
        IAM_LOGI("start");
        static_cast<void>(messenger);
        static_cast<void>(publicKey);
        static_cast<void>(templateIdList);
        return SUCCESS;
    }

    int32_t OnBeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const std::vector<uint8_t> &command) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(publicKey);
        static_cast<void>(command);
        return SUCCESS;
    }

    int32_t OnEndExecute(uint64_t scheduleId, const std::vector<uint8_t> &command) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(command);
        return SUCCESS;
    }

    int32_t OnSetProperty(const std::vector<uint8_t> &properties) override
    {
        IAM_LOGI("start");
        static_cast<void>(properties);
        return SUCCESS;
    }

    int32_t OnGetProperty(const std::vector<uint8_t> &condition, std::vector<uint8_t> &values) override
    {
        IAM_LOGI("start");
        static_cast<void>(condition);
        static_cast<void>(values);
        return SUCCESS;
    }

    int32_t OnSendData(uint64_t scheduleId, const std::vector<uint8_t> &data) override
    {
        IAM_LOGI("start");
        static_cast<void>(scheduleId);
        static_cast<void>(data);
        return SUCCESS;
    }

    sptr<IRemoteObject> AsObject() override
    {
        sptr<IRemoteObject> tmp(nullptr);
        return tmp;
    }
};

std::shared_ptr<ResourceNode> GetResourceNode(Parcel &parcel)
{
    IAM_LOGI("start");
    static std::shared_ptr<ResourceNode> g_ResourceNode;
    if (g_ResourceNode != nullptr) {
        return g_ResourceNode;
    }
    CoAuthInterface::ExecutorRegisterInfo info = {};
    info.authType = static_cast<AuthType>(parcel.ReadInt32());
    info.esl = static_cast<ExecutorSecureLevel>(parcel.ReadInt32());
    info.executorMatcher = parcel.ReadUint32();
    info.executorSensorHint = parcel.ReadUint32();
    info.executorRole = static_cast<ExecutorRole>(parcel.ReadInt32());
    Common::FillFuzzUint8Vector(parcel, info.publicKey);
    
    auto callback = Common::MakeShared<DummyExecutorCallbackInterface>();
    std::vector<uint64_t> templateIdList;
    Common::FillFuzzUint64Vector(parcel, templateIdList);
    std::vector<uint8_t> fwkPublicKey;
    Common::FillFuzzUint8Vector(parcel, fwkPublicKey);
    g_ResourceNode = ResourceNode::MakeNewResource(info, callback, templateIdList, fwkPublicKey);
    return g_ResourceNode;
}

void FuzzResourceNodeGetExecutorIndex(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorIndex();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetOwnerDeviceId(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetOwnerDeviceId();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetOwnerPid(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetOwnerPid();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetAuthType(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetAuthType();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorRole(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorRole();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorSensorHint(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorSensorHint();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorMatcher(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorMatcher();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorEsl(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorEsl();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorPublicKey(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorPublicKey();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetExecutorDeviceUdid(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetExecutorDeviceUdid();
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeBeginExecute(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> publicKey;
    Common::FillFuzzUint8Vector(parcel, publicKey);
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes command(attr);
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->BeginExecute(scheduleId, publicKey, command);
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeSendData(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes data(attr);
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->SendData(scheduleId, data);
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeEndExecute(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t scheduleId = parcel.ReadUint64();
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes command(attr);
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->EndExecute(scheduleId, command);
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeSetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes properties(attr);
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->SetProperty(properties);
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeGetProperty(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<uint8_t> attr;
    Common::FillFuzzUint8Vector(parcel, attr);
    Attributes condition(attr);
    Attributes values;
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->GetProperty(condition, values);
    }
    IAM_LOGI("end");
}

void FuzzResourceNodeDetach(Parcel &parcel)
{
    IAM_LOGI("start");
    auto node = GetResourceNode(parcel);
    if (node != nullptr) {
        node->DetachFromDriver();
    }
    IAM_LOGI("end");
}

using ResourceNodeFuzzFunc = decltype(FuzzResourceNodeGetExecutorIndex);
ResourceNodeFuzzFunc *g_ResourceNodeFuzzFuncs[] = {
    FuzzResourceNodeGetExecutorIndex,
    FuzzResourceNodeGetOwnerDeviceId,
    FuzzResourceNodeGetOwnerPid,
    FuzzResourceNodeGetAuthType,
    FuzzResourceNodeGetExecutorRole,
    FuzzResourceNodeGetExecutorSensorHint,
    FuzzResourceNodeGetExecutorMatcher,
    FuzzResourceNodeGetExecutorEsl,
    FuzzResourceNodeGetExecutorPublicKey,
    FuzzResourceNodeGetExecutorDeviceUdid,
    FuzzResourceNodeBeginExecute,
    FuzzResourceNodeEndExecute,
    FuzzResourceNodeSetProperty,
    FuzzResourceNodeGetProperty,
    FuzzResourceNodeSendData,
    FuzzResourceNodeDetach,
};
} // namespace

void ResourceNodeFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_ResourceNodeFuzzFuncs) / sizeof(ResourceNodeFuzzFunc *));
    auto fuzzFunc = g_ResourceNodeFuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
