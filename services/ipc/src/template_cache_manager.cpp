/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "template_cache_manager.h"

#include <mutex>

#include "os_account_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability_status_change_stub.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "context_pool.h"
#include "resource_node_pool.h"
#include "resource_node_utils.h"
#include "user_idm_database.h"
#include "thread_handler.h"

#define LOG_FILE_ID LOG_FILE_TEMPLATE_CACHE_MANAGER
#define LOG_TAG "USER_AUTH_SA"
namespace OHOS {
namespace UserIam {
namespace UserAuth {
TemplateCacheManager::TemplateCacheManager()
{
    IAM_LOGI("init");
}

TemplateCacheManager &TemplateCacheManager::GetInstance()
{
    static TemplateCacheManager templateCacheManager;
    return templateCacheManager;
}

void TemplateCacheManager::ProcessUserIdChange(const int newUserId)
{
    {
        std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
        if (newUserId == currUserId_) {
            IAM_LOGE("same userId %{public}d", newUserId);
            return;
        }

        IAM_LOGI("begin");
        currUserId_ = newUserId;
    }
    UpdateTemplateCache(FACE);
    UpdateTemplateCache(FINGERPRINT);
    IAM_LOGI("done");
    return;
}

void TemplateCacheManager::UpdateTemplateCache(AuthType authType)
{
    IAM_LOGI("start");
    int32_t currUserId = 0;
    {
        std::lock_guard<std::recursive_mutex> lock(recursiveMutex_);
        currUserId = currUserId_;
    }

    IF_FALSE_LOGE_AND_RETURN(currUserId != INVALID_USER_ID);
    if (authType != FACE && authType != FINGERPRINT) {
        IAM_LOGI("this auth type is not cached");
        return;
    }

    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(currUserId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            currUserId, authType);
        return;
    }

    if (credentialInfos.empty()) {
        IAM_LOGI("user %{public}d has no credential type %{public}d", currUserId, authType);
        ResourceNodePool::Instance().Enumerate([authType](const std::weak_ptr<ResourceNode> &node) {
            auto nodeTmp = node.lock();
            IF_FALSE_LOGE_AND_RETURN(nodeTmp != nullptr);

            if (nodeTmp->GetAuthType() != authType) {
                return;
            }
            IAM_LOGI("clear cached template for type %{public}d", authType);
            ResourceNodeUtils::SetCachedTemplates(nodeTmp->GetExecutorIndex(),
                std::vector<std::shared_ptr<CredentialInfoInterface>>());
        });
        return;
    }

    IAM_LOGI("user %{public}d type %{public}d credential info size %{public}zu",
        currUserId, authType, credentialInfos.size());
    std::map<uint64_t, std::vector<std::shared_ptr<CredentialInfoInterface>>> id2Cred;
    ResultCode result = ResourceNodeUtils::ClassifyCredInfoByExecutor(credentialInfos, id2Cred);
    IF_FALSE_LOGE_AND_RETURN(result == SUCCESS);

    for (auto const &pair : id2Cred) {
        ResourceNodeUtils::SetCachedTemplates(pair.first, pair.second);
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS