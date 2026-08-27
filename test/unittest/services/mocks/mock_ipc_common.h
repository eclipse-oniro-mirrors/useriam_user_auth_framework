/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef MOCK_IPC_COMMON_H
#define MOCK_IPC_COMMON_H

#include <cinttypes>
#include <iremote_stub.h>
#include <optional>
#include <string>
#include <set>

#include "accesstoken_kit.h"
#include "iam_common_defines.h"
#include "nocopyable.h"
#include "user_auth_engine_types.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
enum Permission {
    MANAGE_USER_IDM_PERMISSION,
    USE_USER_IDM_PERMISSION,
    ACCESS_USER_AUTH_INTERNAL_PERMISSION,
    ACCESS_BIOMETRIC_PERMISSION,
    ACCESS_AUTH_RESPOOL,
    ENFORCE_USER_IDM,
    SUPPORT_USER_AUTH,
    IS_SYSTEM_APP,
    CLEAR_REDUNDANCY_PERMISSION,
    USE_USER_ACCESS_MANAGER,
    USER_AUTH_FROM_BACKGROUND,
    ENTERPRISE_DEVICE_MGR,
};

class IpcCommon final : public NoCopyable {
public:
    static int32_t GetCallingUserId(IPCObjectStub &stub, int32_t &userId);
    static int32_t GetActiveUserId(std::optional<int32_t> &userId);
    static int32_t GetAllUserId(std::vector<int32_t> &userIds);
    static int32_t GetUserTypeByUserId(int32_t userId, int32_t &userType);
    static bool CheckPermission(IPCObjectStub &stub, Permission permission);
    static bool GetCallerName(IPCObjectStub &stub, std::string &callerName, int32_t &callerType);
    static bool GetCallerNameByTokenId(uint32_t tokenId, std::string &callerName, int32_t &callerType);
    static bool GetCallingAppID(IPCObjectStub &stub, std::string &callingAppID, std::string &callingAppIdentifier);
    static uint32_t GetAccessTokenId(IPCObjectStub &stub);
    static void SetAccessTokenId(uint32_t tokenId, bool isSetTokenId);
    static void SetSkipCallerFlag(bool isSkip);
    static void SetSkipAccountVerifiedFlag(bool isSkip);
    static void AddPermission(Permission perm);
    static void DeleteAllPermission();
    static uint32_t GetTokenId(IPCObjectStub &stub);
    static void SetSkipUserFlag(bool isSkip);
    static bool CheckForegroundApplication(const std::string &bundleName);
    static bool IsOsAccountVerified(int32_t userId);
    static int32_t GetDirectCallerType(IPCObjectStub &stub);
    static void SetSkipActiveUserIdCallerFlag(bool isSkip);
    static std::optional<EngCallerType> GetEngCallerType(int32_t callerType);

private:
    static std::set<Permission> permSet_;
    static bool isSetTokenId_;
    static uint32_t tokenId_;
    static bool skipFlag_;
    static bool skipCallerFlag_;
    static bool skipAccountVerifiedFlag_;
    static bool skipActiveUserIdFlag_;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // MOCK_IPC_COMMON_H