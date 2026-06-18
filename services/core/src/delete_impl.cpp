/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "delete_impl.h"

#include "credential_info_impl.h"
#include "credential_updated_manager.h"
#include "event_listener_manager.h"
#include "hdi_wrapper.h"
#include "iam_hitrace_helper.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "ipc_common.h"
#include "load_mode_handler.h"
#include "publish_event_adapter.h"
#include "resource_node_utils.h"
#include "schedule_node_helper.h"
#include "thread_handler_manager.h"
#include "update_pin_param_impl.h"
#include "user_idm_database.h"

#define LOG_FILE_ID LOG_FILE_DELETE_IMPL
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
DeleteImpl::DeleteImpl(DeleteParam deletePara) : deletePara_(deletePara)
{
}

DeleteImpl::~DeleteImpl()
{
    Cancel();
}

void DeleteImpl::SetLatestError(int32_t error)
{
    if (error != ResultCode::SUCCESS) {
        latestError_ = error;
    }
}

int32_t DeleteImpl::GetLatestError() const
{
    return latestError_;
}

void DeleteImpl::SetAccessTokenId(uint32_t tokenId)
{
    tokenId_ = tokenId;
}

uint32_t DeleteImpl::GetAccessTokenId() const
{
    return tokenId_;
}

int32_t DeleteImpl::GetUserId() const
{
    return deletePara_.userId;
}

bool DeleteImpl::Start(std::vector<std::shared_ptr<ScheduleNode>> &scheduleList,
    std::shared_ptr<ScheduleNodeCallback> callback, bool &isCredentialDelete,
    std::vector<HdiCredentialInfo> &credentialInfos)
{
    IAM_LOGE("UserId:%{public}d", deletePara_.userId);
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    HdiCredentialOperateResult hdiResult = {};
    IamHitraceHelper traceHelper("hdi DeleteCredential");
    int32_t ret = hdi->DeleteCredential(deletePara_.userId, deletePara_.credentialId, deletePara_.token,
        hdiResult);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("failed to delete credential, error code : %{public}d", ret);
        SetLatestError(ret);
        return false;
    }

    credentialInfos = hdiResult.credentialInfos;
    if (hdiResult.operateType == HdiCredentialOperateType::CREDENTIAL_DELETE) {
        isCredentialDelete = true;
        return DeleteCredential(deletePara_.userId, hdiResult.credentialInfos);
    } else if (hdiResult.operateType == HdiCredentialOperateType::CREDENTIAL_ABANDON) {
        return StartSchedule(deletePara_.userId, hdiResult.scheduleInfo, scheduleList, callback);
    }

    return false;
}

bool DeleteImpl::Update(const std::vector<uint8_t> &scheduleResult, std::shared_ptr<CredentialInfoInterface> &info)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (!hdi) {
        IAM_LOGE("bad hdi");
        return false;
    }

    std::vector<HdiCredentialInfo> credentialInfos;
    auto result = hdi->UpdateAbandonResult(deletePara_.userId, scheduleResult, credentialInfos);
    if (result != HDF_SUCCESS) {
        IAM_LOGE("hdi UpdateAbandonResult failed, err is %{public}d, userId is %{public}d", result,
            deletePara_.userId);
        SetLatestError(result);
        return false;
    }
    
    if (!credentialInfos.empty()) {
        info =  Common::MakeShared<CredentialInfoImpl>(deletePara_.userId, credentialInfos[0]);
        if (info == nullptr) {
            IAM_LOGE("bad alloc");
            return false;
        }
    }
    CredentialUpdatedManager::GetInstance().ProcessCredentialDeleted(deletePara_, deletePara_.credentialId, PIN);
    return true;
}

bool DeleteImpl::Cancel()
{
    return true;
}

bool DeleteImpl::StartSchedule(int32_t userId, HdiScheduleInfo &info,
    std::vector<std::shared_ptr<ScheduleNode>> &scheduleList, std::shared_ptr<ScheduleNodeCallback> callback)
{
    IAM_LOGI("start");
    std::vector<HdiScheduleInfo> infos = {};
    infos.emplace_back(info);

    ScheduleNodeHelper::NodeOptionalPara para;
    para.tokenId = tokenId_;
    para.userId = userId;

    if (!ScheduleNodeHelper::BuildFromHdi(infos, callback, scheduleList, para)) {
        IAM_LOGE("BuildFromHdi failed");
        return false;
    }
    if (scheduleList.size() == 0 || scheduleList[0] == nullptr) {
        IAM_LOGE("Bad Parameter!");
        return false;
    }

    scheduleId_ = scheduleList[0]->GetScheduleId();
    return true;
}

bool DeleteImpl::DeleteCredential(int32_t userId, std::vector<HdiCredentialInfo> &credentialInfos)
{
    IAM_LOGI("start");
    std::vector<std::shared_ptr<CredentialInfoInterface>> list;
    for (auto credentialInfo : credentialInfos) {
        auto info = Common::MakeShared<CredentialInfoImpl>(userId, credentialInfo);
        if (info == nullptr) {
            IAM_LOGE("bad alloc");
            return false;
        }
        list.push_back(info);
    }

    ThreadHandlerManager::GetInstance().PostTaskOnTemporaryThread("DeleteTemplate", [list]() {
        int32_t ret = ResourceNodeUtils::NotifyExecutorToDeleteTemplates(list, "DeleteTemplate");
        if (ret != SUCCESS) {
            IAM_LOGE("NotifyExecutorToDeleteTemplates fail, ret:%{public}d", ret);
        }
    });

    for (const auto &info: list) {
        if (info == nullptr) {
            continue;
        }
        CredentialUpdatedManager::GetInstance().ProcessCredentialDeleted(deletePara_, info->GetCredentialId(),
            info->GetAuthType());
    }
    return true;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS