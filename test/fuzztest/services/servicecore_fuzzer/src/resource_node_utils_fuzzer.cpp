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

#include "resource_node_utils_fuzzer.h"

#include "resource_node_utils.h"

#include "iam_fuzz_test.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "parcel.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_UTILS

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {

class DummyCredentialInfo final : public CredentialInfoInterface {
public:
    DummyCredentialInfo(uint64_t executorIndex, uint64_t templateId, AuthType authType)
        : executorIndex_(executorIndex), templateId_(templateId), authType_(authType) {}
    ~DummyCredentialInfo() override = default;
    uint64_t GetCredentialId() const override { return credentialId_; }
    int32_t GetUserId() const override { return userId_; }
    uint64_t GetExecutorIndex() const override { return executorIndex_; }
    uint64_t GetTemplateId() const override { return templateId_; }
    AuthType GetAuthType() const override { return authType_; }
    uint32_t GetExecutorSensorHint() const override { return 0; }
    uint32_t GetExecutorMatcher() const override { return 0; }
    PinSubType GetAuthSubType() const override { return PIN_SIX; }
    bool GetAbandonFlag() const override { return false; }
    int64_t GetValidPeriod() const override { return 0; }

private:
    int32_t userId_ = 100;
    uint64_t credentialId_ = 0;
    uint64_t executorIndex_;
    uint64_t templateId_;
    AuthType authType_;
};

std::vector<std::shared_ptr<CredentialInfoInterface>> BuildFuzzCredInfos(Parcel &parcel, bool allowNull)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    uint32_t count = parcel.ReadUint32() % 4;
    for (uint32_t i = 0; i < count; ++i) {
        if (allowNull && parcel.ReadBool()) {
            infos.emplace_back(nullptr);
            continue;
        }
        uint64_t executorIndex = parcel.ReadUint64();
        uint64_t templateId = parcel.ReadUint64();
        auto authType = static_cast<AuthType>(parcel.ReadUint32());
        infos.emplace_back(Common::MakeShared<DummyCredentialInfo>(executorIndex, templateId, authType));
    }
    return infos;
}

void FuzzNotifyExecutorToDeleteTemplates(Parcel &parcel)
{
    IAM_LOGI("start");
    auto infos = BuildFuzzCredInfos(parcel, true);
    std::string changeReasonTrace;
    Common::FillFuzzString(parcel, changeReasonTrace);
    ResourceNodeUtils::NotifyExecutorToDeleteTemplates(infos, changeReasonTrace);
    IAM_LOGI("end");
}

void FuzzNotifyExecutorToDeleteTemplatesEmpty(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    std::vector<std::shared_ptr<CredentialInfoInterface>> emptyInfos;
    std::string trace = "empty";
    ResourceNodeUtils::NotifyExecutorToDeleteTemplates(emptyInfos, trace);
    IAM_LOGI("end");
}

void FuzzSendMsgToExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    int32_t commandId = parcel.ReadInt32();
    std::vector<uint8_t> msg;
    Common::FillFuzzUint8Vector(parcel, msg);
    ResourceNodeUtils::SendMsgToExecutor(executorIndex, commandId, msg);
    IAM_LOGI("end");
}

void FuzzSetCachedTemplates(Parcel &parcel)
{
    IAM_LOGI("start");
    uint64_t executorIndex = parcel.ReadUint64();
    auto infos = BuildFuzzCredInfos(parcel, true);
    ResourceNodeUtils::SetCachedTemplates(executorIndex, infos);
    IAM_LOGI("end");
}

void FuzzClassifyCredInfoByExecutor(Parcel &parcel)
{
    IAM_LOGI("start");
    auto infos = BuildFuzzCredInfos(parcel, false);
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> out;
    ResourceNodeUtils::ClassifyCredInfoByExecutor(infos, out);
    IAM_LOGI("end");
}

void FuzzClassifyCredInfoWithNull(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos = {nullptr};
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> out;
    ResourceNodeUtils::ClassifyCredInfoByExecutor(infos, out);
    IAM_LOGI("end");
}

void FuzzNotifyWithNullEntry(Parcel &parcel)
{
    IAM_LOGI("start");
    static_cast<void>(parcel);
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos = {nullptr};
    std::string trace = "null_entry";
    ResourceNodeUtils::NotifyExecutorToDeleteTemplates(infos, trace);
    IAM_LOGI("end");
}

void FuzzClassifyCredInfoMixed(Parcel &parcel)
{
    IAM_LOGI("start");
    std::vector<std::shared_ptr<CredentialInfoInterface>> infos;
    uint64_t indexA = parcel.ReadUint64();
    uint64_t indexB = parcel.ReadUint64();
    infos.emplace_back(Common::MakeShared<DummyCredentialInfo>(indexA, parcel.ReadUint64(), FACE));
    infos.emplace_back(nullptr);
    infos.emplace_back(Common::MakeShared<DummyCredentialInfo>(indexB, parcel.ReadUint64(), PIN));
    infos.emplace_back(Common::MakeShared<DummyCredentialInfo>(indexA, parcel.ReadUint64(), FACE));
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> out;
    ResourceNodeUtils::ClassifyCredInfoByExecutor(infos, out);
    IAM_LOGI("end");
}

using FuzzFunc = decltype(FuzzNotifyExecutorToDeleteTemplates);
FuzzFunc *g_fuzzFuncs[] = {
    FuzzNotifyExecutorToDeleteTemplates,
    FuzzNotifyExecutorToDeleteTemplatesEmpty,
    FuzzSendMsgToExecutor,
    FuzzSetCachedTemplates,
    FuzzClassifyCredInfoByExecutor,
    FuzzClassifyCredInfoWithNull,
    FuzzNotifyWithNullEntry,
    FuzzClassifyCredInfoMixed,
};
} // namespace

void ResourceNodeUtilsFuzzTest(Parcel &parcel)
{
    uint32_t index = parcel.ReadUint32() % (sizeof(g_fuzzFuncs) / sizeof(FuzzFunc *));
    auto fuzzFunc = g_fuzzFuncs[index];
    fuzzFunc(parcel);
    return;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
