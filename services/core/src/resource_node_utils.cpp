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

#include "resource_node_utils.h"

#include "iam_check.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "resource_node_pool.h"

#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_UTILS
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t ResourceNodeUtils::NotifyExecutorToDeleteTemplates(
    const std::vector<std::shared_ptr<CredentialInfoInterface>> &infos, std::string changeReasonTrace)
{
    IAM_LOGI("start");
    if (infos.empty()) {
        IAM_LOGE("bad infos, infos size is 0");
        return INVALID_PARAMETERS;
    }

    for (const auto &info : infos) {
        if (info == nullptr) {
            IAM_LOGE("info is null");
            continue;
        }
        uint64_t executorIndex = info->GetExecutorIndex();

        auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
        if (resourceNode == nullptr) {
            IAM_LOGE("failed to find ****%{public}hx", static_cast<uint16_t>(executorIndex));
            continue;
        }
        Attributes properties;
        properties.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_DEL);
        properties.SetUint64Value(Attributes::ATTR_TEMPLATE_ID, info->GetTemplateId());
        properties.SetStringValue(Attributes::ATTR_TEMPLATE_CHANGE_REASON, changeReasonTrace);
        IamHitraceHelper traceHelper("NotifyExecutorToDeleteTemplates");
        int32_t ret = resourceNode->SetProperty(properties);
        if (ret != SUCCESS) {
            IAM_LOGE("failed to set property to ****%{public}hx", static_cast<uint16_t>(executorIndex));
        }
    }

    return SUCCESS;
}

void ResourceNodeUtils::SendMsgToExecutor(uint64_t executorIndex, int32_t commandId, const std::vector<uint8_t> &msg)
{
    IAM_LOGI("send msg to ****%{public}hx begin", static_cast<uint16_t>(executorIndex));
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("failed to find ****%{public}hx", static_cast<uint16_t>(executorIndex));
        return;
    }
    Attributes properties;
    // In current version, msg type is not set, temporary use PROPER_MODE_FREEZE
    bool setAuthPropertyModeRet =
        properties.SetInt32Value(UserIam::UserAuth::Attributes::ATTR_PROPERTY_MODE, commandId);
    IF_FALSE_LOGE_AND_RETURN(setAuthPropertyModeRet == true);
    bool setExtraInfoRet = properties.SetUint8ArrayValue(UserIam::UserAuth::Attributes::ATTR_EXTRA_INFO, msg);
    IF_FALSE_LOGE_AND_RETURN(setExtraInfoRet == true);
    int32_t ret = resourceNode->SetProperty(properties);
    if (ret != SUCCESS) {
        IAM_LOGE("failed to set property to ****%{public}hx", static_cast<uint16_t>(executorIndex));
        return;
    }
    IAM_LOGI("send msg to ****%{public}hx success", static_cast<uint16_t>(executorIndex));
}

void ResourceNodeUtils::SetCachedTemplates(uint64_t executorIndex,
    const std::vector<std::shared_ptr<CredentialInfoInterface>> &infos)
{
    IAM_LOGI("start");
    auto resourceNode = ResourceNodePool::Instance().Select(executorIndex).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return;
    }

    std::vector<uint64_t> templateIds;
    for (auto &info : infos) {
        if (info == nullptr) {
            IAM_LOGE("info is null");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }

    Attributes attr;
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_SET_CACHED_TEMPLATES);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);

    int32_t result = resourceNode->SetProperty(attr);
    if (result != SUCCESS) {
        IAM_LOGE("set property failed, result = %{public}d", result);
        return;
    }

    IAM_LOGI("success");
}

ResultCode ResourceNodeUtils::ClassifyCredInfoByExecutor(
    const std::vector<std::shared_ptr<CredentialInfoInterface>> &in,
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> &out)
{
    for (auto &cred : in) {
        if (cred == nullptr) {
            IAM_LOGE("cred is null");
            return GENERAL_ERROR;
        }
        uint64_t executorIndex = cred->GetExecutorIndex();
        if (out.find(executorIndex) == out.end()) {
            out[executorIndex] = std::vector<std::shared_ptr<CredentialInfoInterface>>();
        }
        out[executorIndex].push_back(cred);
    }
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS