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

#include "user_auth_service_helper.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "credential_info_interface.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "user_auth_client_defines.h"
#include "user_auth_common_defines.h"
#include "user_auth_helper.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_SERVICE_HELPER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t GetTemplatesByAuthType(int32_t userId, AuthType authType, std::vector<uint64_t> &templateIds)
{
    templateIds.clear();
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
    if (ret != SUCCESS) {
        IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
            userId, authType);
        return GENERAL_ERROR;
    }

    if (credentialInfos.empty()) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return SUCCESS;
    }

    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        if (info == nullptr) {
            IAM_LOGE("info is nullptr");
            continue;
        }
        templateIds.push_back(info->GetTemplateId());
    }

    return SUCCESS;
}

std::string GetAuthParamStr(const AuthParamInner &authParam, std::optional<RemoteAuthParam> &remoteAuthParam)
{
    std::ostringstream authParamString;
    authParamString << "userId:" << authParam.userId << " authType:" << authParam.authType
                    << " authIntent:" << authParam.authIntent << " atl:" << authParam.authTrustLevel
                    << " tokenSchedule:" << UserAuthHelper::TokenScheduleToString(authParam.tokenSchedule);
    if (remoteAuthParam.has_value()) {
        const uint32_t networkIdPrintLen = 4;
        const uint32_t tokenIdMinLen = 2;
        auto verifierNetworkIdStr = remoteAuthParam->verifierNetworkId.value_or("").substr(0, networkIdPrintLen);
        auto collectorNetworkIdStr = remoteAuthParam->collectorNetworkId.value_or("").substr(0, networkIdPrintLen);
        auto tokenIdStr = std::to_string(remoteAuthParam->collectorTokenId.value_or(0));
        if (tokenIdStr.size() > tokenIdMinLen) {
            tokenIdStr = std::string(1, tokenIdStr[0]) + "****" + std::string(1, tokenIdStr[tokenIdStr.size() - 1]);
        } else {
            tokenIdStr = "";
        }

        authParamString << " isRemoteAuth:true" << " verifierNetworkId:" << verifierNetworkIdStr << "****"
            " collectorNetworkId:" << collectorNetworkIdStr << "****" << " collectorTokenId:" << tokenIdStr;
    }
    return authParamString.str();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
