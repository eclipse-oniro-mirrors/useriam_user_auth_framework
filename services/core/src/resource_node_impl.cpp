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

#include "resource_node.h"

#include <cinttypes>
#include <mutex>
#include <unordered_map>

#include "device_manager_util.h"
#include "hdi_wrapper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "remote_msg_util.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class ResourceNodeImpl : public ResourceNode, public NoCopyable {
public:
    ResourceNodeImpl(ExecutorRegisterInfo info, std::shared_ptr<IExecutorCallback> callback);
    ~ResourceNodeImpl() override;

    uint64_t GetExecutorIndex() const override;
    std::string GetOwnerDeviceId() const override;
    uint32_t GetOwnerPid() const override;
    AuthType GetAuthType() const override;
    ExecutorRole GetExecutorRole() const override;
    uint64_t GetExecutorSensorHint() const override;
    uint64_t GetExecutorMatcher() const override;
    ExecutorSecureLevel GetExecutorEsl() const override;
    std::vector<uint8_t> GetExecutorPublicKey() const override;
    std::string GetExecutorDeviceUdid() const override;

    int32_t BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
        const Attributes &command) override;
    int32_t EndExecute(uint64_t scheduleId, const Attributes &command) override;
    int32_t SetProperty(const Attributes &properties) override;
    int32_t GetProperty(const Attributes &condition, Attributes &values) override;
    int32_t SendData(uint64_t scheduleId, const Attributes &data) override;
    void DeleteFromDriver() override;
    void DetachFromDriver() override;
    friend ResourceNode;

private:
    int32_t AddToDriver(std::vector<uint64_t> &templateIdList, std::vector<uint8_t> &fwkPublicKey);
    static void DeleteExecutorFromDriver(uint64_t executorIndex);

    ExecutorRegisterInfo info_;
    std::shared_ptr<IExecutorCallback> callback_;
    uint64_t executorIndex_ {0};
    std::recursive_mutex mutex_;
    bool addedToDriver_ {false};
};

ResourceNodeImpl::ResourceNodeImpl(ExecutorRegisterInfo info, std::shared_ptr<IExecutorCallback> callback)
    : info_(std::move(info)),
      callback_(std::move(callback))
{
    if (info_.deviceUdid.empty()) {
        bool setUdidRet = DeviceManagerUtil::GetInstance().GetLocalDeviceUdid(info_.deviceUdid);
        IF_FALSE_LOGE_AND_RETURN(setUdidRet);
    }
}

ResourceNodeImpl::~ResourceNodeImpl()
{
    if (!addedToDriver_) {
        return;
    }

    DeleteExecutorFromDriver(executorIndex_);
}

uint64_t ResourceNodeImpl::GetExecutorIndex() const
{
    return executorIndex_;
}

std::string ResourceNodeImpl::GetOwnerDeviceId() const
{
    return {};
}

uint32_t ResourceNodeImpl::GetOwnerPid() const
{
    return SUCCESS;
}

AuthType ResourceNodeImpl::GetAuthType() const
{
    return info_.authType;
}

ExecutorRole ResourceNodeImpl::GetExecutorRole() const
{
    return info_.executorRole;
}

uint64_t ResourceNodeImpl::GetExecutorSensorHint() const
{
    return info_.executorSensorHint;
}

uint64_t ResourceNodeImpl::GetExecutorMatcher() const
{
    return info_.executorMatcher;
}

ExecutorSecureLevel ResourceNodeImpl::GetExecutorEsl() const
{
    return info_.esl;
}

std::vector<uint8_t> ResourceNodeImpl::GetExecutorPublicKey() const
{
    return info_.publicKey;
}

std::string ResourceNodeImpl::GetExecutorDeviceUdid() const
{
    return info_.deviceUdid;
}

int32_t ResourceNodeImpl::BeginExecute(uint64_t scheduleId, const std::vector<uint8_t> &publicKey,
    const Attributes &command)
{
    IAM_LOGD("start");
    if (callback_ != nullptr) {
        return callback_->OnBeginExecute(scheduleId, publicKey, command.Serialize());
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::EndExecute(uint64_t scheduleId, const Attributes &command)
{
    IAM_LOGD("start");
    if (callback_ != nullptr) {
        return callback_->OnEndExecute(scheduleId, command.Serialize());
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::SetProperty(const Attributes &properties)
{
    IAM_LOGD("start");
    if (callback_ != nullptr) {
        return callback_->OnSetProperty(properties.Serialize());
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::GetProperty(const Attributes &condition, Attributes &values)
{
    IAM_LOGD("start");
    if (callback_ != nullptr) {
        std::vector<uint8_t> attribute;
        auto ret = callback_->OnGetProperty(condition.Serialize(), attribute);
        if (ret == SUCCESS) {
            values = Attributes(attribute);
        }
        return ret;
    }
    return GENERAL_ERROR;
}

int32_t ResourceNodeImpl::SendData(uint64_t scheduleId, const Attributes &data)
{
    IAM_LOGD("start");
    
    if (callback_ != nullptr) {
        return callback_->OnSendData(scheduleId, data.Serialize());
    }
    return GENERAL_ERROR;
}

void ResourceNodeImpl::DeleteFromDriver()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (addedToDriver_) {
        DeleteExecutorFromDriver(executorIndex_);
    }
    addedToDriver_ = false;
}

void ResourceNodeImpl::DetachFromDriver()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    addedToDriver_ = false;
}

int32_t ResourceNodeImpl::AddToDriver(std::vector<uint64_t> &templateIdList, std::vector<uint8_t> &fwkPublicKey)
{
    HdiExecutorRegisterInfo hdiInfo = {
        .authType = static_cast<HdiAuthType>(info_.authType),
        .executorRole = static_cast<HdiExecutorRole>(info_.executorRole),
        .executorSensorHint = info_.executorSensorHint,
        .executorMatcher = info_.executorMatcher,
        .esl = static_cast<HdiExecutorSecureLevel>(info_.esl),
        .maxTemplateAcl = info_.maxTemplateAcl,
        .publicKey = info_.publicKey,
        .deviceUdid = info_.deviceUdid,
        .signedRemoteExecutorInfo = info_.signedRemoteExecutorInfo,
    };

    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }

    int32_t result = hdi->AddExecutor(hdiInfo, executorIndex_, fwkPublicKey, templateIdList);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi add executor failed with code %{public}d, authType: %{public}d,"
            " executorRole: %{public}d, esl: %{public}d, acl: %{public}d", result, info_.authType,
            info_.executorRole, info_.esl, info_.maxTemplateAcl);
        return GENERAL_ERROR;
    }
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    addedToDriver_ = true;
    IAM_LOGI("hdi AddExecutor ****%{public}hx success", static_cast<uint16_t>(executorIndex_));
    return SUCCESS;
}

void ResourceNodeImpl::DeleteExecutorFromDriver(uint64_t executorIndex)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return;
    }

    auto result = hdi->DeleteExecutor(executorIndex);
    if (result != HDF_SUCCESS) {
        HILOG_COMM_ERROR("hdi delete executor ****%{public}hx with %{public}d",
            static_cast<uint16_t>(executorIndex), result);
        return;
    }
    IAM_LOGI("hdi DeleteExecutor ****%{public}hx success", static_cast<uint16_t>(executorIndex));
}

std::shared_ptr<ResourceNode> ResourceNode::MakeNewResource(const ExecutorRegisterInfo &info,
    const std::shared_ptr<IExecutorCallback> &callback, std::vector<uint64_t> &templateIdList,
    std::vector<uint8_t> &fwkPublicKey)
{
    auto node = Common::MakeShared<ResourceNodeImpl>(info, callback);
    if (node == nullptr) {
        IAM_LOGE("bad alloc");
        return nullptr;
    }

    int32_t result = node->AddToDriver(templateIdList, fwkPublicKey);
    if (result != 0) {
        IAM_LOGE("hdi error with %{public}d", result);
        return nullptr;
    }

    return node;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
