/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "user_auth_service.h"

#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "ipc_common.h"
#include "user_auth_client_defines.h"
#include "user_auth_engine.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
bool CheckPinAlgoType(uint32_t pinAlgoType)
{
    if (pinAlgoType != PinEncrypAlgoType::AES_GCM &&
        pinAlgoType != PinEncrypAlgoType::SM4) {
        IAM_LOGE("bad pinAlgoType value:%{public}d", pinAlgoType);
        return false;
    }
    return true;
}

bool CheckParam(const IpcGlobalConfigParam &ipcGlobalConfigParam)
{
    if (ipcGlobalConfigParam.userIds.size() > MAX_USER || ipcGlobalConfigParam.authTypes.size() > MAX_AUTH_TYPE_SIZE ||
        ipcGlobalConfigParam.authTypes.size() == 0) {
        IAM_LOGE("bad global config param");
        return false;
    }
    switch (static_cast<GlobalConfigType>(ipcGlobalConfigParam.type)) {
        case GlobalConfigType::PIN_EXPIRED_PERIOD:
        case GlobalConfigType::PIN_ALGO_TYPE:
        case GlobalConfigType::DISABLE_PIN_DELETION:
            if (ipcGlobalConfigParam.authTypes.size() != 1 || ipcGlobalConfigParam.authTypes[0] != PIN) {
                IAM_LOGE("bad authTypes, type=%{public}d", ipcGlobalConfigParam.type);
                return false;
            }
            break;
        case GlobalConfigType::ENABLE_STATUS:
            break;
        default:
            IAM_LOGE("bad global config type, type=%{public}d", ipcGlobalConfigParam.type);
            return false;
    }
    return true;
}

bool FillGlobalConfigValue(const IpcGlobalConfigParam &ipcGlobalConfigParam, EngGlobalConfigValue &value)
{
    switch (static_cast<GlobalConfigType>(ipcGlobalConfigParam.type)) {
        case GlobalConfigType::PIN_EXPIRED_PERIOD:
            value.pinExpiredPeriod = ipcGlobalConfigParam.value.pinExpiredPeriod;
            break;
        case GlobalConfigType::ENABLE_STATUS:
            value.enableStatus = ipcGlobalConfigParam.value.enableStatus;
            break;
        case GlobalConfigType::PIN_ALGO_TYPE:
            IF_FALSE_LOGE_AND_RETURN_VAL(CheckPinAlgoType(ipcGlobalConfigParam.value.pinAlgoType), false);
            value.pinAlgoType = ipcGlobalConfigParam.value.pinAlgoType;
            break;
        case GlobalConfigType::DISABLE_PIN_DELETION:
            value.disablePinDeletion = ipcGlobalConfigParam.value.disablePinDeletion;
            break;
        default:
            IAM_LOGE("bad global config type");
            return false;
    }
    return true;
}

bool UserAuthService::CheckSetGlobalConfigPermission()
{
    bool hasPermissionUserAccessManager = IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER);
    bool hasPermissionUserAuthInternal = IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION);
    bool hasPermissionEnterpriseDeviceMgr = IpcCommon::CheckPermission(*this, ENTERPRISE_DEVICE_MGR);
    return hasPermissionUserAccessManager ||
        (hasPermissionUserAuthInternal && hasPermissionEnterpriseDeviceMgr);
}

int32_t UserAuthService::SetGlobalConfigParam(const IpcGlobalConfigParam &ipcGlobalConfigParam)
{
    IAM_LOGI("start, GlobalConfigType is %{public}d, userIds size %{public}zu, authTypes size %{public}zu",
        ipcGlobalConfigParam.type, ipcGlobalConfigParam.userIds.size(), ipcGlobalConfigParam.authTypes.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(CheckSetGlobalConfigPermission(), CHECK_PERMISSION_FAILED);
    IF_FALSE_LOGE_AND_RETURN_VAL(CheckParam(ipcGlobalConfigParam), INVALID_PARAMETERS);

    EngGlobalConfigParam paramConfig = {};
    IF_FALSE_LOGE_AND_RETURN_VAL(FillGlobalConfigValue(ipcGlobalConfigParam, paramConfig.value), INVALID_PARAMETERS);

    paramConfig.type = static_cast<int32_t>(ipcGlobalConfigParam.type);
    paramConfig.userIds = ipcGlobalConfigParam.userIds;
    for (const auto authType : ipcGlobalConfigParam.authTypes) {
        paramConfig.authTypes.push_back(static_cast<AuthType>(authType));
    }
    int32_t result = GetUserAuthEngine().SetGlobalConfigParam(paramConfig);
    IF_FALSE_LOGE_AND_RETURN_VAL(result == SUCCESS, result);
    return SUCCESS;
}

int32_t UserAuthService::GetGlobalConfigParamInner(int32_t userId, int32_t authType, int32_t type,
    IpcGlobalConfigValue &ipcGlobalConfigValue)
{
    EngGlobalConfigValue engConfigValue = {};
    int32_t result = GetUserAuthEngine().GetGlobalConfigParam(userId, authType, type, engConfigValue);
    if (result != SUCCESS) {
        IAM_LOGE("GetGlobalConfigParam from engine failed, userId=%{public}d, result=%{public}d", userId, result);
        return result;
    }

    switch (static_cast<GlobalConfigType>(type)) {
        case GlobalConfigType::PIN_EXPIRED_PERIOD:
            ipcGlobalConfigValue.pinExpiredPeriod = engConfigValue.pinExpiredPeriod;
            break;
        case GlobalConfigType::ENABLE_STATUS:
            ipcGlobalConfigValue.enableStatus = engConfigValue.enableStatus;
            break;
        case GlobalConfigType::PIN_ALGO_TYPE:
            ipcGlobalConfigValue.pinAlgoType = engConfigValue.pinAlgoType;
            break;
        case GlobalConfigType::DISABLE_PIN_DELETION:
            ipcGlobalConfigValue.disablePinDeletion = engConfigValue.disablePinDeletion;
            break;
        default:
            IAM_LOGE("bad global config type, type=%{public}d", type);
            return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

int32_t UserAuthService::GetGlobalConfigParam(int32_t userId, int32_t authType, int32_t type,
    IpcGlobalConfigValue &ipcGlobalConfigValue, int32_t &funcResult)
{
    IAM_LOGI("start, userId=%{public}d, authType=%{public}d, type=%{public}d", userId, authType, type);
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER), CHECK_PERMISSION_FAILED);
    funcResult = GetGlobalConfigParamInner(userId, authType, type, ipcGlobalConfigValue);
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
