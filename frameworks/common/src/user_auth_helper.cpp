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
 
#define LOG_FILE_ID LOG_FILE_USER_AUTH_HELPER
#define LOG_TAG "USER_AUTH_COMMON"
 
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
        authType != AuthType::COMPANION_DEVICE && authType != AuthType::CUSTOM_AUTH) {
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
