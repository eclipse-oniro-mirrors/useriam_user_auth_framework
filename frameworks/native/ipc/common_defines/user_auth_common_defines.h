/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

/**
 * @file user_auth_common_defines.h
 *
 * @brief Some common defines in IAM.
 * @since 3.1
 * @version 3.2
 */

#ifndef USER_AUTH_COMMON_DEFINES_H
#define USER_AUTH_COMMON_DEFINES_H

#include <cstddef>
#include <cstdint>

#include <string>
#include <vector>

#include "iam_common_defines.h"
#include "user_auth_client_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

const std::string NOTICE_VERSION_STR = "1";
const std::string CMD_NOTIFY_AUTH_START = "CMD_NOTIFY_AUTH_START";
const std::string CMD_NOTIFY_AUTH_RESULT = "CMD_NOTIFY_AUTH_RESULT";
const std::string CMD_NOTIFY_AUTH_TIP = "CMD_NOTIFY_AUTH_TIP";
const uint64_t BAD_CONTEXT_ID = 0;

/**
 * @brief Notice type for user authentication.
 */
enum NoticeType : int32_t {
    /** notice from widget. */
    WIDGET_NOTICE = 1,
};

/**
 * @brief Auth parameter.
 */
struct AuthParamInner {
    /** user id */
    int32_t userId;
    /** is userId specified */
    bool isUserIdSpecified;
    /** challenge value */
    std::vector<uint8_t> challenge;
    /** Credential type for authentication. */
    AuthType authType;
    /** Credential type for authentication. */
    std::vector<AuthType> authTypes;
    /** Trust level of authentication result. */
    AuthTrustLevel authTrustLevel;
    /** Reuse unlock authentication result. */
    ReuseUnlockResult reuseUnlockResult;
    /** Auth intention. */
    AuthIntent authIntent;
    /** Skip locked biometric authentication */
    bool skipLockedBiometricAuth {false};
    /** Used to specify the credential Ids for authentication */
    std::vector<uint64_t> credentialIdList;
    /** Remote token id */
    std::optional<uint32_t> remoteTokenId;
};

/**
 * @brief EnrolledId digest and credential count.
 */
struct EnrolledState {
    /** The credential digest. */
    uint64_t credentialDigest {0};
    /** The credential count */
    uint16_t credentialCount {0};
};

/**
 * @brief Authentication lock state.
 */
struct AuthLockState {
    /** Authentication lock state. */
    bool isLocked{0};
    /** Remain attempts. */
    int32_t remainingAuthAttempts{5};
    /** Lockout duration */
    int32_t lockoutDuration{0};
};

/**
 * @brief Auth widget parameter.
 */
struct WidgetParamInner {
    /** Title of widget. */
    std::string title;
    /** The description text of navigation button. */
    std::string navigationButtonText;
    /** Full screen or not. */
    WindowModeType windowMode;
    /** Default has't context. */
    bool hasContext {false};
};

/**
 * @brief Cancel reason for user authentication.
 */
enum CancelReason : int32_t {
    /** notice from widget. */
    ORIGINAL_CANCEL = 0,
    /** notice from widget. */
    MODAL_CREATE_ERROR = 1,
    /** notice from widget. */
    MODAL_RUN_ERROR = 2,
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // USER_AUTH_COMMON_DEFINES_H
