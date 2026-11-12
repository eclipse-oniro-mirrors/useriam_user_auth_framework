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

#include "user_auth_helper.h"

#include <cinttypes>
 
#include "iam_logger.h"
 
#define LOG_TAG "USER_AUTH_COMMON"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_HELPER

namespace OHOS {
namespace UserIam {
namespace UserAuth {

int32_t UserAuthHelper::GetResultCodeV10(int32_t result)
{
    if (result == CHECK_PERMISSION_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED);
    }
    if (result == INVALID_PARAMETERS) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_INVALID_PARAM);
    }
    if (result == CHECK_SYSTEM_APP_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED);
    }
    if (result == CAPABILITY_NOT_SUPPORTED) {
        return static_cast<int32_t>(UserAuthResultCode::OHOS_CAPABILITY_NOT_SUPPORTED);
    }
    if (result == HARDWARE_NOT_SUPPORTED) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    if (result > (INT32_MAX - static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN))) {
        return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
    }
    int32_t resultCodeV10 = result + static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN);
    if (resultCodeV10 >= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MIN) &&
        resultCodeV10 <= static_cast<int32_t>(UserAuthResultCode::RESULT_CODE_V10_MAX)) {
        IAM_LOGI("version GetResultCodeV10 resultCodeV10 result: %{public}d", resultCodeV10);
        return resultCodeV10;
    }
    IAM_LOGE("version GetResultCodeV10 resultCodeV10 error");
    return static_cast<int32_t>(UserAuthResultCode::GENERAL_ERROR);
}

UserAuthResultCode UserAuthHelper::GetResultCodeV16(int32_t result)
{
    static const std::map<int32_t, UserAuthResultCode> resultV16Map = {
        { ResultCode::SUCCESS, UserAuthResultCode::SUCCESS },
        { ResultCode::FAIL, UserAuthResultCode::FAIL },
        { ResultCode::GENERAL_ERROR, UserAuthResultCode::GENERAL_ERROR },
        { ResultCode::CANCELED, UserAuthResultCode::CANCELED },
        { ResultCode::TIMEOUT, UserAuthResultCode::TIMEOUT },
        { ResultCode::TYPE_NOT_SUPPORT, UserAuthResultCode::TYPE_NOT_SUPPORT },
        { ResultCode::TRUST_LEVEL_NOT_SUPPORT, UserAuthResultCode::TRUST_LEVEL_NOT_SUPPORT },
        { ResultCode::BUSY, UserAuthResultCode::BUSY },
        { ResultCode::INVALID_PARAMETERS, UserAuthResultCode::OHOS_INVALID_PARAM },
        { ResultCode::LOCKED, UserAuthResultCode::LOCKED },
        { ResultCode::NOT_ENROLLED, UserAuthResultCode::NOT_ENROLLED },
        { ResultCode::CANCELED_FROM_WIDGET, UserAuthResultCode::CANCELED_FROM_WIDGET },
        { ResultCode::PIN_EXPIRED, UserAuthResultCode::PIN_EXPIRED },
        { ResultCode::AUTH_TOKEN_CHECK_FAILED, UserAuthResultCode::AUTH_TOKEN_CHECK_FAILED },
        { ResultCode::AUTH_TOKEN_EXPIRED, UserAuthResultCode::AUTH_TOKEN_EXPIRED },
        { ResultCode::REUSE_AUTH_RESULT_FAILED, UserAuthResultCode::REUSE_AUTH_RESULT_FAILED },
        { ResultCode::CAPABILITY_NOT_SUPPORTED, UserAuthResultCode::OHOS_CAPABILITY_NOT_SUPPORTED },
        { ResultCode::CHECK_PERMISSION_FAILED, UserAuthResultCode::OHOS_CHECK_PERMISSION_FAILED },
        { ResultCode::CHECK_SYSTEM_APP_FAILED, UserAuthResultCode::OHOS_CHECK_SYSTEM_APP_FAILED },
    };
    auto it = resultV16Map.find(result);
    if (it == resultV16Map.end()) {
        IAM_LOGE("GetResultCodeV16 unmapped result: %{public}d", result);
        return UserAuthResultCode::GENERAL_ERROR;
    }
    IAM_LOGI("GetResultCodeV16 result: %{public}d, resultCodeV16: %{public}d", result,
        static_cast<int32_t>(it->second));
    return it->second;
}

UserAuthResultCode UserAuthHelper::GetResultCodeV26(int32_t result)
{
    if (result == ResultCode::AUTH_TOKEN_NOT_IN_WINDOW) {
        return UserAuthResultCode::AUTH_TOKEN_NOT_IN_WINDOW;
    }
    if (result == ResultCode::AUTH_TOKEN_CREDENTIAL_INVALID) {
        return UserAuthResultCode::AUTH_TOKEN_CREDENTIAL_INVALID;
    }
    return GetResultCodeV16(result);
}

int32_t UserAuthHelper::GetResultCodeV20(int32_t result)
{
    if (result == INVALID_PARAMETERS) {
        return static_cast<int32_t>(UserAuthResultCode::PARAM_VERIFIED_FAILED);
    }
    if (result == REUSE_AUTH_RESULT_FAILED) {
        return static_cast<int32_t>(UserAuthResultCode::REUSE_AUTH_RESULT_FAILED);
    }
    return GetResultCodeV10(result);
}

int32_t UserAuthHelper::GetResultCodeV21(int32_t result)
{
    if (result == TYPE_NOT_SUPPORT) {
        return static_cast<int32_t>(UserAuthResultCode::TYPE_NOT_SUPPORT);
    }
    if (result == NOT_ENROLLED) {
        return static_cast<int32_t>(UserAuthResultCode::NOT_ENROLLED);
    }
    return GetResultCodeV20(result);
}
 
bool UserAuthHelper::CheckUserAuthType(int32_t authType)
{
    if (authType != AuthType::PIN && authType != AuthType::FACE &&
        authType != AuthType::FINGERPRINT && authType != AuthType::PRIVATE_PIN &&
        authType != AuthType::COMPANION_DEVICE && authType != AuthType::CUSTOM_AUTH &&
        authType != AuthType::RECOVERY_KEY) {
        IAM_LOGE("authType check fail:%{public}d", authType);
        return false;
    }
    return true;
}
 
bool UserAuthHelper::CheckAuthTrustLevel(uint32_t authTrustLevel)
{
    if (authTrustLevel != AuthTrustLevel::ATL1 && authTrustLevel != AuthTrustLevel::ATL2 &&
        authTrustLevel != AuthTrustLevel::ATL3 && authTrustLevel != AuthTrustLevel::ATL4) {
        IAM_LOGE("authTrustLevel check fail:%{public}d", authTrustLevel);
        return false;
    }
    return true;
}

bool UserAuthHelper::CheckAuthTokenParam(const std::vector<uint8_t> &authToken)
{
    if (authToken.size() == 0 || authToken.size() > MAX_AUTH_TOKEN_LEN) {
        IAM_LOGE("bad authToken, size:%{public}zu", authToken.size());
        return false;
    }
    return true;
}

bool UserAuthHelper::CheckChallengeParam(const std::vector<uint8_t> &challenge)
{
    if (challenge.size() > MAX_CHALLENG_LEN) {
        IAM_LOGE("bad challenge, size:%{public}zu", challenge.size());
        return false;
    }
    return true;
}
bool UserAuthHelper::SetTokenScheduleAttr(const std::optional<TokenSchedule> &schedule, Attributes &extraInfo)
{
    if (!schedule.has_value()) {
        return true;
    }
    if (schedule->hasValidStartTime &&
        !extraInfo.SetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_VALID_START, schedule->validStartTime)) {
        IAM_LOGE("set schedule attr fail");
        return false;
    }
    if (schedule->hasValidEndTime &&
        !extraInfo.SetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_VALID_END, schedule->validEndTime)) {
        IAM_LOGE("set schedule attr fail");
        return false;
    }
    if (!schedule->windowConfig.has_value()) {
        return true;
    }
    if (!extraInfo.SetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_REPEAT_INTERVAL,
        schedule->windowConfig->repeatInterval)) {
        IAM_LOGE("set schedule repeatInterval fail");
        return false;
    }
    if (!extraInfo.SetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_WINDOW_DURATION,
        schedule->windowConfig->windowDuration)) {
        IAM_LOGE("set schedule windowDuration fail");
        return false;
    }
    return true;
}

bool UserAuthHelper::GetTokenScheduleAttr(const Attributes &extraInfo, TokenSchedule &schedule)
{
    int64_t validStartTime = 0;
    int64_t validEndTime = 0;
    int64_t repeatInterval = 0;
    schedule.hasValidStartTime =
        extraInfo.GetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_VALID_START, validStartTime);
    schedule.hasValidEndTime = extraInfo.GetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_VALID_END, validEndTime);
    bool hasRepeatInterval =
        extraInfo.GetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_REPEAT_INTERVAL, repeatInterval);
    if (!schedule.hasValidStartTime && !schedule.hasValidEndTime && !hasRepeatInterval) {
        return false;
    }
    schedule.validStartTime = validStartTime;
    schedule.validEndTime = validEndTime;
    schedule.windowConfig = std::nullopt;
    if (!hasRepeatInterval) {
        return true;
    }
    RedemptionWindow window = {};
    window.repeatInterval = repeatInterval;
    int64_t windowDuration = 0;
    if (!extraInfo.GetInt64Value(Attributes::ATTR_TOKEN_SCHEDULE_WINDOW_DURATION, windowDuration)) {
        IAM_LOGE("get schedule windowDuration fail");
        return false;
    }
    window.windowDuration = windowDuration;
    schedule.windowConfig = window;
    return true;
}

int32_t UserAuthHelper::CheckTokenSchedule(const std::optional<TokenSchedule> &schedule)
{
    if (!schedule.has_value()) {
        return SUCCESS;
    }
    if (schedule->hasValidStartTime && schedule->hasValidEndTime) {
        if (schedule->validEndTime <= schedule->validStartTime) {
            IAM_LOGE("validEndTime must be greater than validStartTime");
            return INVALID_PARAMETERS;
        }
        if (schedule->validEndTime - schedule->validStartTime > MAX_TOKEN_SCHEDULE_SPAN_MS) {
            IAM_LOGE("schedule span must not exceed 30 days");
            return INVALID_PARAMETERS;
        }
    }
    if (!schedule->windowConfig.has_value()) {
        return SUCCESS;
    }
    const RedemptionWindow &window = schedule->windowConfig.value();
    if (window.repeatInterval < MIN_REPEAT_INTERVAL_MS) {
        IAM_LOGE("repeatInterval must not be less than 1 hour");
        return INVALID_PARAMETERS;
    }
    if (window.windowDuration <= 0) {
        IAM_LOGE("windowDuration must be greater than 0");
        return INVALID_PARAMETERS;
    }
    if (window.windowDuration > window.repeatInterval) {
        IAM_LOGE("windowDuration must not be greater than repeatInterval");
        return INVALID_PARAMETERS;
    }
    return SUCCESS;
}

 bool UserAuthHelper::CheckReuseUnlockResult(ReuseUnlockResult reuseUnlockResult)
 {
    if (reuseUnlockResult.reuseMode != ReuseMode::AUTH_TYPE_RELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::AUTH_TYPE_IRRELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT &&
        reuseUnlockResult.reuseMode != ReuseMode::CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT) {
        IAM_LOGE("reuseMode check fail:%{public}u", reuseUnlockResult.reuseMode);
        return false;
    }
    if (reuseUnlockResult.reuseDuration <= 0 || reuseUnlockResult.reuseDuration > MAX_ALLOWABLE_REUSE_DURATION) {
        IAM_LOGE("reuseDuration check fail:%{public}" PRIu64, reuseUnlockResult.reuseDuration);
        return false;
    }
    return true;
}

size_t UserAuthHelper::GetUtf8CharCount(const std::string &str)
{
    // 统计显示字符数，编码规则解析
    // UTF-8采用变长字节编码，单个字节的最高位为1时表示后续字节采用多字节编码。
    const unsigned char UTF8_TWO_BYTE_MASK = 0xE0; // 0xE0：对应二进制1110 xxxx，表示字符需要2个字节编码。
    const unsigned char UTF8_THREE_BYTE_MASK = 0xF0; // 0xF0：对应二进制1111 0xxx，表示字符需要3个字节编码。
    const unsigned char UTF8_FOUR_BYTE_MASK = 0xF8; // 0xF8：对应二进制1111 1xxx，表示字符需要4个字节编码。
    const unsigned char UTF8_TWO_BYTE_START = 0xC0;
    const unsigned char UTF8_THREE_BYTE_START = 0xE0;
    const unsigned char UTF8_FOUR_BYTE_START = 0xF0;
    const size_t ONE_BYTE_UTF8 = 1;
    const size_t TWO_BYTE_UTF8 = 2;
    const size_t THREE_BYTE_UTF8 = 3;
    const size_t FOUR_BYTE_UTF8 = 4;
    
    size_t charCount = 0;
    for (size_t i = 0; i < str.size();) {
        unsigned char c = static_cast<unsigned char>(str[i]);
        if ((c & UTF8_TWO_BYTE_MASK) == UTF8_TWO_BYTE_START) {
            i += TWO_BYTE_UTF8;
        } else if ((c & UTF8_THREE_BYTE_MASK) == UTF8_THREE_BYTE_START) {
            i += THREE_BYTE_UTF8;
        } else if ((c & UTF8_FOUR_BYTE_MASK) == UTF8_FOUR_BYTE_START) {
            i += FOUR_BYTE_UTF8;
        } else {
            i += ONE_BYTE_UTF8;
        }
        charCount++;
    }
    return charCount;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
