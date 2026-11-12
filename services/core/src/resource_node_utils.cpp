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

#include <algorithm>

#include "resource_node_utils.h"

#include "iam_check.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "resource_node_pool.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_RESOURCE_NODE_UTILS

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

    std::vector<std::shared_ptr<CredentialInfoInterface>> sortedInfos = infos;
    std::sort(sortedInfos.begin(), sortedInfos.end(),
        [](const std::shared_ptr<CredentialInfoInterface> &a,
            const std::shared_ptr<CredentialInfoInterface> &b) -> bool {
            if (a == nullptr || b == nullptr) {
                return false;
            }
            return a->GetAbandonFlag() > b->GetAbandonFlag();
        });

    for (const auto &info : sortedInfos) {
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
        properties.SetBoolValue(Attributes::ATTR_ABANDON_FLAG, info->GetAbandonFlag());
        IamHitraceHelper traceHelper("NotifyExecutorToDeleteTemplates");
        Attributes values;
        int32_t ret = resourceNode->SetProperty(properties, values);
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
    Attributes values;
    int32_t ret = resourceNode->SetProperty(properties, values);
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

    Attributes values;
    int32_t result = resourceNode->SetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("set property failed, result = %{public}d", result);
        return;
    }

    IAM_LOGI("success");
}

int32_t ResourceNodeUtils::SendCommandToExecutor(AuthType authType, ExecutorRole role, uint32_t propertyMode,
    const std::vector<uint8_t> &extraInfo, std::vector<uint8_t> &extraOut)
{
    IAM_LOGI("send command to executor, authType:%{public}d, role:%{public}d, propertyMode:%{public}u",
        static_cast<int32_t>(authType), static_cast<int32_t>(role), propertyMode);
    std::vector<std::weak_ptr<ResourceNode>> authTypeNodes;
    ResourceNodePool::Instance().GetResourceNodeByTypeAndRole(authType, role, authTypeNodes);
    if (authTypeNodes.empty()) {
        IAM_LOGE("executor not found, authType:%{public}d, role:%{public}d",
            static_cast<int32_t>(authType), static_cast<int32_t>(role));
        return GENERAL_ERROR;
    }
    auto resourceNode = authTypeNodes[0].lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode expired");
        return GENERAL_ERROR;
    }

    Attributes attrIn = {};
    attrIn.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, propertyMode);
    attrIn.SetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraInfo);
    Attributes attrOut = {};
    int32_t ret = resourceNode->SetProperty(attrIn, attrOut);
    if (ret != SUCCESS) {
        IAM_LOGE("SetProperty failed, ret=%{public}d", ret);
        return ret;
    }
    attrOut.GetUint8ArrayValue(Attributes::ATTR_EXTRA_INFO, extraOut);
    return ret;
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