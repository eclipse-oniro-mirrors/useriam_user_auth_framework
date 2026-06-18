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
#include "load_mode_client_util.h"

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "parameter.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_LOAD_MODE_CLIENT_UTIL
#define LOG_TAG "USER_AUTH_SDK"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
#ifdef ENABLE_DYNAMIC_LOAD
bool CheckSelfPermission(const std::string &permission)
{
    using namespace Security::AccessToken;
    uint32_t tokenId = static_cast<uint32_t>(IPCSkeleton::GetSelfTokenID());
    if (AccessTokenKit::VerifyAccessToken(tokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("failed to check permission %{public}s", permission.c_str());
        return false;
    }
    return true;
}

bool IsUserIamDeamonProcess()
{
    constexpr uint32_t MAX_VALUE_LEN = 128;
    const char *IS_PIN_ENROLLED_KEY = "persist.useriam.isPinEnrolled";
    char valueBuffer[MAX_VALUE_LEN] = { 0 };
    int32_t ret = GetParameter(IS_PIN_ENROLLED_KEY, "false", valueBuffer, MAX_VALUE_LEN);
    if (ret < 0) {
        IAM_LOGE("get parameter failed, ret:%{public}d", ret);
        return false;
    }
    return std::string(valueBuffer) == "true";
}

bool HasAnyPermission(const std::vector<std::string> &permissions)
{
    for (const auto &permission : permissions) {
        if (CheckSelfPermission(permission)) {
            return true;
        }
    }

    return false;
}

int32_t LoadModeUtil::GetProxyNullResultCode(const char *funcName, const std::vector<std::string> &permissions)
{
    IF_FALSE_LOGE_AND_RETURN_VAL(funcName != nullptr, GENERAL_ERROR);
    if (IsUserIamDeamonProcess()) {
        IAM_LOGE("%{public}s, user iam is deamon process, proxy should not be null", funcName);
        return GENERAL_ERROR;
    }

    if (!HasAnyPermission(permissions)) {
        IAM_LOGE("%{public}s, check permission failed", funcName);
        return CHECK_PERMISSION_FAILED;
    }

    IAM_LOGE("%{public}s, useriam is not deamon process and pin is not enrolled", funcName);
    return NOT_ENROLLED;
}
#else
int32_t LoadModeUtil::GetProxyNullResultCode(const char *funcName, const std::vector<std::string> &permissions)
{
    static_cast<void>(funcName);
    static_cast<void>(permissions);
    IAM_LOGE("proxy is nullptr");
    return GENERAL_ERROR;
}
#endif
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS