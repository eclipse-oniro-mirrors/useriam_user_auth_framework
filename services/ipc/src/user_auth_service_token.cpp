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

#include "user_auth_service.h"

#include <cinttypes>

#include "accesstoken_kit.h"
#include "auth_common.h"
#include "auth_widget_helper.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "ipc_common.h"
#include "user_auth_engine.h"
#include "user_auth_helper.h"
#include "user_auth_engine_types.h"
#include "user_auth_helper.h"
#include "xcollie_helper.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {

bool UserAuthService::SetAuthTokenAttr(const EngUserAuthTokenPlain &tokenPlain, const std::vector<uint8_t> &rootSecret,
    Attributes &extraInfo)
{
    bool setTokenVersionRet = extraInfo.SetUint32Value(Attributes::ATTR_TOKEN_VERSION, tokenPlain.version);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTokenVersionRet == true, false);
    bool setUserIdRet = extraInfo.SetInt32Value(Attributes::ATTR_USER_ID, tokenPlain.userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setUserIdRet == true, false);
    bool setChallengeRet = extraInfo.SetUint8ArrayValue(Attributes::ATTR_CHALLENGE, tokenPlain.challenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(setChallengeRet == true, false);
    bool setTimeStampRet = extraInfo.SetUint64Value(Attributes::ATTR_TOKEN_TIME_INTERVAL, tokenPlain.timeInterval);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTimeStampRet == true, false);
    bool setTrustLevelRet = extraInfo.SetUint32Value(Attributes::ATTR_AUTH_TRUST_LEVEL, tokenPlain.authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTrustLevelRet == true, false);
    bool setAuthTypeRet = extraInfo.SetInt32Value(Attributes::ATTR_AUTH_TYPE, tokenPlain.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypeRet == true, false);
    bool setTokenTypeRet = extraInfo.SetInt32Value(Attributes::ATTR_TOKEN_TYPE, tokenPlain.tokenType);
    IF_FALSE_LOGE_AND_RETURN_VAL(setTokenTypeRet == true, false);
    bool setSecureUidRet = extraInfo.SetUint64Value(Attributes::ATTR_SEC_USER_ID, tokenPlain.secureUid);
    IF_FALSE_LOGE_AND_RETURN_VAL(setSecureUidRet == true, false);
    bool setEnrolledIdRet = extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, tokenPlain.enrolledId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setEnrolledIdRet == true, false);
    bool setCredentialIdRet = extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_ID, tokenPlain.credentialId);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialIdRet == true, false);
    if (rootSecret.size() != 0) {
        bool setRootSecret = extraInfo.SetUint8ArrayValue(Attributes::ATTR_ROOT_SECRET, rootSecret);
        IF_FALSE_LOGE_AND_RETURN_VAL(setRootSecret == true, false);
    }
    if (tokenPlain.tokenType == TOKEN_TYPE_SCHEDULED_AUTH) {
        return UserAuthHelper::SetTokenScheduleAttr(tokenPlain.tokenSchedule, extraInfo);
    }
    return true;
}

int32_t UserAuthService::VerifyAuthToken(const std::vector<uint8_t> &tokenIn, uint64_t allowableDuration,
    const sptr<IVerifyTokenCallback> &verifyTokenCallback)
{
    IAM_LOGI("start, duration:%{public}" PRIu64 ", tokenIn size:%{public}zu.", allowableDuration, tokenIn.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(verifyTokenCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_PERMISSION_FAILED, extraInfo.Serialize());
        return CHECK_PERMISSION_FAILED;
    }
    if (!IpcCommon::IsSystemCaller(*this)) {
        IAM_LOGE("caller is not systemApp.");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_SYSTEM_APP_FAILED, extraInfo.Serialize());
        return CHECK_SYSTEM_APP_FAILED;
    }
    if (!UserAuthHelper::CheckAuthTokenParam(tokenIn)) {
        verifyTokenCallback->OnVerifyTokenResult(INVALID_PARAMETERS, extraInfo.Serialize());
        return INVALID_PARAMETERS;
    }

    EngUserAuthTokenPlain tokenPlain = {};
    std::vector<uint8_t> rootSecret = {};
    int32_t result = GetUserAuthEngine().VerifyAuthToken(tokenIn, allowableDuration, tokenPlain, rootSecret);
    if (result != SUCCESS) {
        IAM_LOGE("VerifyAuthToken failed result:%{public}d", result);
        verifyTokenCallback->OnVerifyTokenResult(result, extraInfo.Serialize());
        return result;
    }
    if (!SetAuthTokenAttr(tokenPlain, rootSecret, extraInfo)) {
        IAM_LOGE("SetAuthTokenAttr failed");
        verifyTokenCallback->OnVerifyTokenResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    verifyTokenCallback->OnVerifyTokenResult(SUCCESS, extraInfo.Serialize());
    return SUCCESS;
}

int32_t UserAuthService::RedeemScheduledAuthToken(const std::vector<uint8_t> &challenge,
    const std::vector<uint8_t> &scheduleToken,
    const sptr<IVerifyTokenCallback> &verifyTokenCallback)
{
    IAM_LOGI("start, challenge size:%{public}zu, scheduleToken size:%{public}zu", challenge.size(),
        scheduleToken.size());
    Common::XCollieHelper xcollie(__FUNCTION__, Common::API_CALL_TIMEOUT);
    IF_FALSE_LOGE_AND_RETURN_VAL(verifyTokenCallback != nullptr, INVALID_PARAMETERS);

    Attributes extraInfo;
    if (!IpcCommon::CheckPermission(*this, USE_USER_ACCESS_MANAGER)) {
        IAM_LOGE("failed to check permission");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_PERMISSION_FAILED, extraInfo.Serialize());
        return CHECK_PERMISSION_FAILED;
    }
    if (!IpcCommon::IsSystemCaller(*this)) {
        IAM_LOGE("caller is not systemApp.");
        verifyTokenCallback->OnVerifyTokenResult(CHECK_SYSTEM_APP_FAILED, extraInfo.Serialize());
        return CHECK_SYSTEM_APP_FAILED;
    }
    if (!UserAuthHelper::CheckAuthTokenParam(scheduleToken) || challenge.empty() ||
        !UserAuthHelper::CheckChallengeParam(challenge)) {
        verifyTokenCallback->OnVerifyTokenResult(INVALID_PARAMETERS, extraInfo.Serialize());
        return INVALID_PARAMETERS;
    }
    std::vector<uint8_t> authTokenOut = {};
    int32_t result = GetUserAuthEngine().RedeemScheduleToken(challenge, scheduleToken, authTokenOut);
    if (result != SUCCESS) {
        IAM_LOGE("RedeemScheduleToken failed result:%{public}d", result);
        verifyTokenCallback->OnVerifyTokenResult(result, extraInfo.Serialize());
        return result;
    }
    if (!extraInfo.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, authTokenOut)) {
        IAM_LOGE("set ATTR_SIGNATURE fail");
        verifyTokenCallback->OnVerifyTokenResult(GENERAL_ERROR, extraInfo.Serialize());
        return GENERAL_ERROR;
    }
    verifyTokenCallback->OnVerifyTokenResult(SUCCESS, extraInfo.Serialize());
    return SUCCESS;
}

int32_t UserAuthService::QueryReusableAuthResult(const IpcAuthParamInner &ipcAuthParamInner,
    std::vector<uint8_t> &token)
{
    if (!IpcCommon::CheckPermission(*this, ACCESS_USER_AUTH_INTERNAL_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        return CHECK_PERMISSION_FAILED;
    }

    if (!(IpcCommon::GetDirectCallerType(*this) == Security::AccessToken::TOKEN_HAP &&
        IpcCommon::CheckPermission(*this, IS_SYSTEM_APP))) {
        IAM_LOGE("caller is not systemApp.");
        return CHECK_SYSTEM_APP_FAILED;
    }

    AuthParamInner authParam = {};
    InitAuthParam(ipcAuthParamInner, authParam);
    if (!UserAuthHelper::CheckAuthTrustLevel(static_cast<uint32_t>(authParam.authTrustLevel))) {
        IAM_LOGE("invalid authTrustLevel: %{public}u", static_cast<uint32_t>(authParam.authTrustLevel));
        return TRUST_LEVEL_NOT_SUPPORT;
    }
    for (const auto &type : authParam.authTypes) {
        if (!UserAuthHelper::CheckUserAuthType(static_cast<int32_t>(type))) {
            IAM_LOGE("invalid authType: %{public}d", static_cast<int32_t>(type));
            return TYPE_NOT_SUPPORT;
        }
    }
    if (!authParam.isUserIdSpecified) {
        if (IpcCommon::GetCallingUserId(*this, authParam.userId) != SUCCESS) {
            IAM_LOGE("failed to get callingUserId");
            return GENERAL_ERROR;
        }
    }

    EngReuseUnlockInfo reuseResultInfo = {};
    int32_t result = AuthWidgetHelper::QueryReusableAuthResult(authParam.userId, authParam, reuseResultInfo);
    if (result != SUCCESS) {
        IAM_LOGE("CheckReuseUnlockResult failed result:%{public}d userId:%{public}d", result,
            ipcAuthParamInner.userId);
        return result;
    }

    token = reuseResultInfo.token;
    return SUCCESS;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
