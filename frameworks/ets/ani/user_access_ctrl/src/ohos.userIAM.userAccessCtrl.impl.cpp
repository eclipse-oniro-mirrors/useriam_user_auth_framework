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

#include "ohos.userIAM.userAccessCtrl.impl.hpp"

#include "taihe/runtime.hpp"

#include <cinttypes>
#include <future>
#include <map>
#include <mutex>

#include "attributes.h"
#include "iam_check.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iam_ptr.h"
#include "user_access_ctrl_client.h"

#define LOG_TAG "USER_ACCESS_CTRL_ANI"
#define LOG_FILE_ID LOG_FILE_USER_ACCESS_CTRL_ANI_IMPL

namespace userAccessCtrl = ohos::userIAM::userAccessCtrl;
namespace userAuth = ohos::userIAM::userAuth::userAuth;
namespace UserAuth = OHOS::UserIam::UserAuth;
using namespace taihe;
using namespace OHOS::UserIam::Common;
namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum class JsResultCode : int32_t {
    OHOS_CHECK_PERMISSION_FAILED = 201,
    OHOS_CHECK_SYSTEM_APP_FAILED = 202,
    OHOS_INVALID_PARAM = 401,
    GENERAL_ERROR = 12500002,
    AUTH_TOKEN_CHECK_FAILED = 12500015,
    AUTH_TOKEN_EXPIRED = 12500016,
};

struct VerifyAuthTokenResult {
    int32_t resultCode;
    std::vector<uint8_t> extraInfo;
};

class VerifyAuthTokenCallback : public VerifyTokenCallback {
public:
    VerifyAuthTokenCallback()
    {
        future_ = promise_.get_future().share();
    }

    void OnResult(int32_t result, const Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        IAM_LOGI("result: %{public}d, resultSet_: %{public}d", result, resultSet_);
        if (!resultSet_) {
            VerifyAuthTokenResult verifyAuthTokenResult { result, extraInfo.Serialize() };
            promise_.set_value(verifyAuthTokenResult);
            resultSet_ = true;
        }
    }

    std::shared_future<VerifyAuthTokenResult> GetFuture()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return future_;
    }

private:
    std::mutex mutex_;
    std::promise<VerifyAuthTokenResult> promise_;
    std::shared_future<VerifyAuthTokenResult> future_;
    bool resultSet_ = false;
};

bool ConvertAllowableDuration(int32_t allowableDuration, uint64_t &outAllowableDurationUint64)
{
    constexpr const double maxAllowableDuration = 24 * 60 * 60 * 1000;
    if (allowableDuration <= 0 || allowableDuration > maxAllowableDuration) {
        IAM_LOGE("allowableDuration check fail:%{public}d", allowableDuration);
        return false;
    }
    outAllowableDurationUint64 = static_cast<uint64_t>(allowableDuration);
    return true;
}

bool CheckAuthTokenLen(std::vector<uint8_t> &authToken)
{
    constexpr const size_t maxAuthTokenLen = 1024;
    if (authToken.size() > maxAuthTokenLen) {
        IAM_LOGE("authToken length check fail:%{public}zu", authToken.size());
        return false;
    }
    return true;
}

bool ConvertAuthTrustLevel(int32_t authTrustLevel, userAuth::AuthTrustLevel &authTrustLevelOut)
{
    switch (authTrustLevel) {
        case AuthTrustLevel::ATL1:
            authTrustLevelOut = userAuth::AuthTrustLevel::key_t::ATL1;
            return true;
        case AuthTrustLevel::ATL2:
            authTrustLevelOut = userAuth::AuthTrustLevel::key_t::ATL2;
            return true;
        case AuthTrustLevel::ATL3:
            authTrustLevelOut = userAuth::AuthTrustLevel::key_t::ATL3;
            return true;
        case AuthTrustLevel::ATL4:
            authTrustLevelOut = userAuth::AuthTrustLevel::key_t::ATL4;
            return true;
        default:
            IAM_LOGE("invalid authTrustLevel:%{public}d", authTrustLevel);
            return false;
    }
}

bool ConvertUserAuthType(int32_t userAuthType, userAuth::UserAuthType &userAuthTypeOut)
{
    switch (userAuthType) {
        case AuthType::PIN:
            userAuthTypeOut = userAuth::UserAuthType::key_t::PIN;
            return true;
        case AuthType::FACE:
            userAuthTypeOut = userAuth::UserAuthType::key_t::FACE;
            return true;
        case AuthType::FINGERPRINT:
            userAuthTypeOut = userAuth::UserAuthType::key_t::FINGERPRINT;
            return true;
        case AuthType::PRIVATE_PIN:
            userAuthTypeOut = userAuth::UserAuthType::key_t::PRIVATE_PIN;
            return true;
        case AuthType::COMPANION_DEVICE:
            userAuthTypeOut = userAuth::UserAuthType::key_t::COMPANION_DEVICE;
            return true;
        default:
            IAM_LOGE("invalid userAuthType:%{public}d", userAuthType);
            return false;
    }
}

bool ConvertAuthTokenType(int32_t authTokenType, userAccessCtrl::AuthTokenType &authTokenTypeOut)
{
    switch (authTokenType) {
        case AuthTokenType::TOKEN_TYPE_LOCAL_AUTH:
            authTokenTypeOut = userAccessCtrl::AuthTokenType::key_t::TOKEN_TYPE_LOCAL_AUTH;
            return true;
        case AuthTokenType::TOKEN_TYPE_LOCAL_RESIGN:
            authTokenTypeOut = userAccessCtrl::AuthTokenType::key_t::TOKEN_TYPE_LOCAL_RESIGN;
            return true;
        case AuthTokenType::TOKEN_TYPE_LOCAL_COAUTH:
            authTokenTypeOut = userAccessCtrl::AuthTokenType::key_t::TOKEN_TYPE_COAUTH;
            return true;
        default:
            IAM_LOGE("invalid authTokenType:%{public}d", authTokenType);
            return false;
    }
}

bool FillAniAuthToken(const std::vector<uint8_t> &extraInfo, userAccessCtrl::AuthToken &authToken)
{
    Attributes attr(extraInfo);

    std::vector<uint8_t> localChallenge;
    bool getChallengeRet = attr.GetUint8ArrayValue(Attributes::ATTR_CHALLENGE, localChallenge);
    IF_FALSE_LOGE_AND_RETURN_VAL(getChallengeRet, false);
    authToken.challenge = array_view<uint8_t>(localChallenge);

    int32_t localAuthTrustLevel;
    bool getAuthTrustLevelRet = attr.GetInt32Value(Attributes::ATTR_AUTH_TRUST_LEVEL, localAuthTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTrustLevelRet, false);
    bool convertAuthTrustLevelRet = ConvertAuthTrustLevel(localAuthTrustLevel, authToken.authTrustLevel);
    IF_FALSE_LOGE_AND_RETURN_VAL(convertAuthTrustLevelRet, false);

    int32_t localAuthType;
    bool getAuthTypeRet = attr.GetInt32Value(Attributes::ATTR_AUTH_TYPE, localAuthType);
    IF_FALSE_LOGE_AND_RETURN_VAL(getAuthTypeRet, false);
    bool convertUserAuthTypeRet = ConvertUserAuthType(localAuthType, authToken.authType);
    IF_FALSE_LOGE_AND_RETURN_VAL(convertUserAuthTypeRet, false);

    int32_t localTokenType;
    bool getTokenTypeRet = attr.GetInt32Value(Attributes::ATTR_TOKEN_TYPE, localTokenType);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenTypeRet, false);
    bool convertAuthTokenTypeRet = ConvertAuthTokenType(localTokenType, authToken.tokenType);
    IF_FALSE_LOGE_AND_RETURN_VAL(convertAuthTokenTypeRet, false);

    int32_t userId = 0;
    bool getUserIdRet = attr.GetInt32Value(Attributes::ATTR_USER_ID, userId);
    IF_FALSE_LOGE_AND_RETURN_VAL(getUserIdRet, false);
    authToken.userId = userId;

    bool getTokenTimeIntervalRet = attr.GetInt64Value(Attributes::ATTR_TOKEN_TIME_INTERVAL, authToken.timeInterval);
    IF_FALSE_LOGE_AND_RETURN_VAL(getTokenTimeIntervalRet, false);

    int64_t secureUid;
    bool getSecureUidRet = attr.GetInt64Value(Attributes::ATTR_SEC_USER_ID, secureUid);
    if (!getSecureUidRet) {
        IAM_LOGE("optional: ATTR_SEC_USER_ID is not set");
    } else {
        authToken.secureUid = optional<int64_t>::make(secureUid);
    }

    int64_t enrolledId;
    bool getEnrolledIdRet = attr.GetInt64Value(Attributes::ATTR_CREDENTIAL_DIGEST, enrolledId);
    if (!getEnrolledIdRet) {
        IAM_LOGE("optional: ATTR_CREDENTIAL_DIGEST is not set");
    } else {
        authToken.enrolledId = optional<int64_t>::make(enrolledId);
    }

    int64_t credentialId;
    bool getCredentialIdRet = attr.GetInt64Value(Attributes::ATTR_CREDENTIAL_ID, credentialId);
    if (!getCredentialIdRet) {
        IAM_LOGE("optional: ATTR_CREDENTIAL_ID is not set");
    } else {
        authToken.credentialId = optional<int64_t>::make(credentialId);
    }

    return true;
}

ResultCode VerifyAuthTokenSyncInner(array_view<uint8_t> authToken, int32_t allowableDuration,
    userAccessCtrl::AuthToken &authTokenOut)
{
    int32_t maxWaitTime = 10000; // 10 seconds
    IAM_LOGD("start");
    std::shared_ptr<VerifyAuthTokenCallback> callback = MakeShared<VerifyAuthTokenCallback>();
    IF_FALSE_LOGE_AND_RETURN_VAL(callback != nullptr, ResultCode::GENERAL_ERROR);

    std::vector<uint8_t> localAuthToken(authToken.begin(), authToken.end());
    uint64_t allowableDurationUint64 = 0;
    if (!CheckAuthTokenLen(localAuthToken) || !ConvertAllowableDuration(allowableDuration, allowableDurationUint64)) {
        return ResultCode::INVALID_PARAMETERS;
    }

    UserAccessCtrlClient::GetInstance().VerifyAuthToken(localAuthToken, allowableDurationUint64, callback);
    auto future = callback->GetFuture();
    auto result = future.wait_for(std::chrono::milliseconds(maxWaitTime));
    if (result == std::future_status::timeout) {
        IAM_LOGE("verifyAuthToken timeout");
        return ResultCode::TIMEOUT;
    }

    VerifyAuthTokenResult verifyAuthTokenResult = future.get();
    if (verifyAuthTokenResult.resultCode != ResultCode::SUCCESS) {
        IAM_LOGE("verifyAuthToken resultCode error:%{public}d", verifyAuthTokenResult.resultCode);
        return static_cast<ResultCode>(verifyAuthTokenResult.resultCode);
    }
    bool fillAniAuthTokenRet = FillAniAuthToken(verifyAuthTokenResult.extraInfo, authTokenOut);
    IF_FALSE_LOGE_AND_RETURN_VAL(fillAniAuthTokenRet, ResultCode::GENERAL_ERROR);

    IAM_LOGD("success");
    return ResultCode::SUCCESS;
}

void ThrowBusinessError(ResultCode ret)
{
    const std::map<ResultCode, std::pair<JsResultCode, std::string>> result2Pair = {
        { ResultCode::INVALID_PARAMETERS, { JsResultCode::OHOS_INVALID_PARAM, "Invalid authentication parameters." } },
        { ResultCode::CHECK_PERMISSION_FAILED, { JsResultCode::OHOS_CHECK_PERMISSION_FAILED, "Permission denied." } },
        { ResultCode::CHECK_SYSTEM_APP_FAILED,
            { JsResultCode::OHOS_CHECK_SYSTEM_APP_FAILED, "The caller is not a system application." } },
        { ResultCode::GENERAL_ERROR, { JsResultCode::GENERAL_ERROR, "Unknown errors." } },
        { ResultCode::AUTH_TOKEN_CHECK_FAILED,
            { JsResultCode::AUTH_TOKEN_CHECK_FAILED,
                "Operation failed because of authToken integrity check failed." } },
        { ResultCode::AUTH_TOKEN_EXPIRED,
            { JsResultCode::AUTH_TOKEN_EXPIRED, "Operation failed because of authToken has expired." } }
    };

    if (ret == ResultCode::SUCCESS) {
        return;
    }

    auto pair = result2Pair.find(ret);
    if (pair == result2Pair.end()) {
        pair = result2Pair.find(ResultCode::GENERAL_ERROR);
    }
    IF_FALSE_LOGE_AND_RETURN(pair != result2Pair.end());
    IAM_LOGE("ThrowBusinessError, result: %{public}d, errorCode: %{public}d, errmsg: %{public}s", pair->first,
        pair->second.first, pair->second.second.c_str());
    set_business_error(static_cast<int32_t>(pair->second.first), pair->second.second);
}

userAccessCtrl::AuthToken VerifyAuthTokenSync(array_view<uint8_t> authToken, double allowableDuration)
{
    IAM_LOGI("start");
    userAccessCtrl::AuthToken authTokenOut = {
        array_view<uint8_t>(nullptr, 0),
        userAuth::AuthTrustLevel::key_t::ATL1,
        userAuth::UserAuthType::key_t::PIN,
        userAccessCtrl::AuthTokenType::key_t::TOKEN_TYPE_LOCAL_AUTH,
    };

    ResultCode ret = VerifyAuthTokenSyncInner(authToken, allowableDuration, authTokenOut);
    if (ret != ResultCode::SUCCESS) {
        ThrowBusinessError(ret);
        return authTokenOut;
    }
    IAM_LOGI("success");
    return authTokenOut;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

namespace {
userAccessCtrl::AuthToken verifyAuthTokenSync(array_view<uint8_t> authToken, double allowableDuration)
{
    return UserAuth::VerifyAuthTokenSync(authToken, allowableDuration);
}
} // namespace
TH_EXPORT_CPP_API_verifyAuthTokenSync(verifyAuthTokenSync);
