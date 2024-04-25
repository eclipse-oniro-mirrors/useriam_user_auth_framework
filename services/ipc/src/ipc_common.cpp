/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ipc_common.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"
#include "app_mgr_interface.h"
#include "iam_common_defines.h"
#include "iam_logger.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#include "os_account_info.h"
#include "user_auth_hdi.h"
#endif // HAS_OS_ACCOUNT_PART
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace PermissionString {
    const std::string MANAGE_USER_IDM_PERMISSION = "ohos.permission.MANAGE_USER_IDM";
    const std::string USE_USER_IDM_PERMISSION = "ohos.permission.USE_USER_IDM";
    const std::string ACCESS_USER_AUTH_INTERNAL_PERMISSION = "ohos.permission.ACCESS_USER_AUTH_INTERNAL";
    const std::string ACCESS_BIOMETRIC_PERMISSION = "ohos.permission.ACCESS_BIOMETRIC";
    const std::string ACCESS_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
    const std::string ENFORCE_USER_IDM = "ohos.permission.ENFORCE_USER_IDM";
    const std::string SUPPORT_USER_AUTH = "ohos.permission.SUPPORT_USER_AUTH";
}

namespace {
    // process white list of allowing to call, <processUid, processName>
    const std::vector<std::pair<int32_t, std::string>> manageUserIdmWhiteLists = {
        {3058, "accountmgr"},
    };

    const std::vector<std::pair<int32_t, std::string>> enforceUserIdmWhiteLists = {
        {3058, "accountmgr"},
    };
}

int32_t IpcCommon::GetCallingUserId(IPCObjectStub &stub, int32_t &userId)
{
    if (userId != 0) {
        return SUCCESS;
    }
    uint32_t tokenId = GetAccessTokenId(stub);
    using namespace Security::AccessToken;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != ATokenTypeEnum::TOKEN_HAP) {
        IAM_LOGE("failed to get calling type");
        return TYPE_NOT_SUPPORT;
    }
    HapTokenInfo hapTokenInfo;
    int result = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get hap token info, result = %{public}d", result);
        return TYPE_NOT_SUPPORT;
    }
    userId = static_cast<int32_t>(hapTokenInfo.userID);
    IAM_LOGI("get callingUserId is %{public}d", userId);
    return SUCCESS;
}

int32_t IpcCommon::GetActiveUserId(std::optional<int32_t> &userId)
{
    if (userId.has_value() && userId.value() != 0) {
        return SUCCESS;
    }
    std::vector<int32_t> ids;
#ifdef HAS_OS_ACCOUNT_PART
    ErrCode queryRet = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (queryRet != ERR_OK || ids.empty()) {
        IAM_LOGE("failed to query active account id");
        return GENERAL_ERROR;
    }
#else  // HAS_OS_ACCOUNT_PART
    const int32_t DEFAULT_OS_ACCOUNT_ID = 0;
    ids.push_back(DEFAULT_OS_ACCOUNT_ID);
    IAM_LOGI("there is no os account part, use default id");
#endif // HAS_OS_ACCOUNT_PART
    userId = ids.front();
    return SUCCESS;
}

int32_t IpcCommon::GetAllUserId(std::vector<int32_t> &userIds)
{
#ifdef HAS_OS_ACCOUNT_PART
    std::vector<OHOS::AccountSA::OsAccountInfo> accountInfos = {};
    ErrCode ret = AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accountInfos);
    if (ret != ERR_OK) {
        IAM_LOGE("failed to query all account id ret %{public}d ", ret);
        return GENERAL_ERROR;
    }

    if (accountInfos.empty()) {
        IAM_LOGE("accountInfos count %{public}zu", accountInfos.size());
        return SUCCESS;
    }

    std::transform(accountInfos.begin(), accountInfos.end(), std::back_inserter(userIds),
        [](auto &iter) { return iter.GetLocalId(); });
#else
    const int32_t DEFAULT_OS_ACCOUNT_ID = 0;
    userIds.push_back(DEFAULT_OS_ACCOUNT_ID);
#endif

    return SUCCESS;
}

static HdiUserType MapOsAccountTypeToUserType(int32_t userId, AccountSA::OsAccountType osAccountType)
{
    if (osAccountType == AccountSA::OsAccountType::PRIVATE) {
        return HdiUserType::PRIVATE;
    } else if (userId == MAIN_USER_ID) {
        return HdiUserType::MAIN;
    } else {
        return HdiUserType::SUB;
    }
}

int32_t IpcCommon::GetUserTypeByUserId(int32_t userId, int32_t &userType)
{
#ifdef HAS_OS_ACCOUNT_PART
    AccountSA::OsAccountType osAccountType;
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountType(userId, osAccountType);
    if (ret != ERR_OK) {
        IAM_LOGE("failed to get osAccountType for userId %d, error code: %d", userId, ret);
        return TYPE_NOT_SUPPORT;
    }
    userType = MapOsAccountTypeToUserType(userId, osAccountType);
    IAM_LOGI("userType:%{public}d", userType);
#else
    const int32_t DEFAULT_OS_ACCOUNT_TYPE = 0;
    userType = DEFAULT_OS_ACCOUNT_TYPE;
#endif

    return SUCCESS;
}

bool IpcCommon::CheckForegroundApplication(const std::string &bundleName)
{
    sptr<ISystemAbilityManager> samgrClient = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrClient == nullptr) {
        IAM_LOGI("Get system ability manager failed");
        return false;
    }
    sptr<AppExecFwk::IAppMgr> iAppManager =
        iface_cast<AppExecFwk::IAppMgr>(samgrClient->GetSystemAbility(APP_MGR_SERVICE_ID));
    if (iAppManager == nullptr) {
        IAM_LOGI("Failed to get ability manager service");
        return false;
    }
    std::vector<AppExecFwk::AppStateData> foregroundAppList;
    iAppManager->GetForegroundApplications(foregroundAppList);
    auto it = std::find_if(foregroundAppList.begin(), foregroundAppList.end(), [bundleName] (auto foregroundApp) {
        return bundleName.compare(foregroundApp.bundleName) == 0;
    });
    if (it == foregroundAppList.end()) {
        IAM_LOGI("app : %{public}s is not foreground", bundleName.c_str());
        return false;
    }
    return true;
}

bool IpcCommon::CheckPermission(IPCObjectStub &stub, Permission permission)
{
    switch (permission) {
        case MANAGE_USER_IDM_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::MANAGE_USER_IDM_PERMISSION) &&
                CheckNativeCallingProcessWhiteList(stub, permission);
        case USE_USER_IDM_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::USE_USER_IDM_PERMISSION);
        case ACCESS_USER_AUTH_INTERNAL_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::ACCESS_USER_AUTH_INTERNAL_PERMISSION);
        case ACCESS_BIOMETRIC_PERMISSION:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::ACCESS_BIOMETRIC_PERMISSION);
        case ACCESS_AUTH_RESPOOL:
            return CheckDirectCaller(stub, PermissionString::ACCESS_AUTH_RESPOOL);
        case ENFORCE_USER_IDM:
            return CheckDirectCaller(stub, PermissionString::ENFORCE_USER_IDM) &&
                CheckNativeCallingProcessWhiteList(stub, permission);
        case SUPPORT_USER_AUTH:
            return CheckDirectCallerAndFirstCallerIfSet(stub, PermissionString::SUPPORT_USER_AUTH);
        case IS_SYSTEM_APP:
            return CheckCallerIsSystemApp(stub);
        case CLEAR_REDUNDANCY_PERMISSION:
            return CheckDirectCaller(stub, PermissionString::ENFORCE_USER_IDM);
        default:
            IAM_LOGE("failed to check permission");
            return false;
    }
}

uint32_t IpcCommon::GetAccessTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetFirstTokenID();
    IAM_LOGI("get first caller tokenId: %{public}u", tokenId);
    if (tokenId == 0) {
        IAM_LOGI("no first caller, get direct caller tokenId: %{public}u", tokenId);
        tokenId = stub.GetCallingTokenID();
    }
    return tokenId;
}

uint32_t IpcCommon::GetTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetCallingTokenID();
    IAM_LOGI("get tokenId: %{public}u", tokenId);
    return tokenId;
}

std::vector<std::pair<int32_t, std::string>> IpcCommon::GetWhiteLists(Permission permission)
{
    switch (permission) {
        case MANAGE_USER_IDM_PERMISSION:
            return manageUserIdmWhiteLists;
        case ENFORCE_USER_IDM:
            return enforceUserIdmWhiteLists;
        case CLEAR_REDUNDANCY_PERMISSION:
        case USE_USER_IDM_PERMISSION:
        case ACCESS_USER_AUTH_INTERNAL_PERMISSION:
        case ACCESS_BIOMETRIC_PERMISSION:
        case ACCESS_AUTH_RESPOOL:
        case SUPPORT_USER_AUTH:
        case IS_SYSTEM_APP:
        default:
            IAM_LOGE("the permission has no white lists");
            return {};
    }
}

bool IpcCommon::CheckNativeCallingProcessWhiteList(IPCObjectStub &stub, Permission permission)
{
    uint32_t tokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callingType != ATokenTypeEnum::TOKEN_NATIVE) {
        IAM_LOGE("failed to get calling type");
        return false;
    }
    NativeTokenInfo nativeTokenInfo;
    int result = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get native token info, result = %{public}d", result);
        return false;
    }

    std::vector<std::pair<int32_t, std::string>> whiteLists = IpcCommon::GetWhiteLists(permission);
    std::string processName = nativeTokenInfo.processName;
    int32_t processUid = stub.GetCallingUid();
    for (const auto &whiteList : whiteLists) {
        if (whiteList.first == processUid && whiteList.second == processName) {
            return true;
        }
    }
    IAM_LOGE("failed to check process white list");
    return false;
}

bool IpcCommon::CheckDirectCallerAndFirstCallerIfSet(IPCObjectStub &stub, const std::string &permission)
{
    uint32_t firstTokenId = stub.GetFirstTokenID();
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    if ((firstTokenId != 0 && AccessTokenKit::VerifyAccessToken(firstTokenId, permission) != RET_SUCCESS) ||
        AccessTokenKit::VerifyAccessToken(callingTokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("failed to check permission");
        return false;
    }
    return true;
}

bool IpcCommon::CheckDirectCaller(IPCObjectStub &stub, const std::string &permission)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    if (AccessTokenKit::VerifyAccessToken(callingTokenId, permission) != RET_SUCCESS) {
        IAM_LOGE("failed to check permission");
        return false;
    }
    return true;
}

bool IpcCommon::CheckCallerIsSystemApp(IPCObjectStub &stub)
{
    uint32_t callingTokenId = stub.GetCallingTokenID();
    using namespace Security::AccessToken;
    uint64_t fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    bool checkRet = TokenIdKit::IsSystemAppByFullTokenID(fullTokenId);
    ATokenTypeEnum callingType = AccessTokenKit::GetTokenTypeFlag(callingTokenId);
    if (checkRet && callingType == ATokenTypeEnum::TOKEN_HAP) {
        IAM_LOGI("the caller is system application");
        return true;
    }
    return false;
}

bool IpcCommon::GetCallerName(IPCObjectStub &stub, std::string &callerName, int32_t &callerType)
{
    callerType = UserAuthCallerType::TOKEN_INVALID;
    uint32_t tokenId = GetAccessTokenId(stub);
    using namespace Security::AccessToken;
    ATokenTypeEnum callerTypeTemp = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (callerTypeTemp == ATokenTypeEnum::TOKEN_HAP) {
        callerType = UserAuthCallerType::TOKEN_HAP;
        HapTokenInfo hapTokenInfo;
        int result = AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
        if (result != SUCCESS) {
            IAM_LOGE("failed to get hap token info, result = %{public}d", result);
            return false;
        }
        callerName = hapTokenInfo.bundleName;
        IAM_LOGI("caller bundleName is %{public}s", callerName.c_str());
        return true;
    } else if (callerTypeTemp == ATokenTypeEnum::TOKEN_NATIVE) {
        callerType = UserAuthCallerType::TOKEN_NATIVE;
        NativeTokenInfo nativeTokenInfo;
        int res = AccessTokenKit::GetNativeTokenInfo(tokenId, nativeTokenInfo);
        if (res != SUCCESS) {
            IAM_LOGE("failed to get native token info, res = %{public}d", res);
            return false;
        }
        callerName = nativeTokenInfo.processName;
        IAM_LOGI("caller processName is %{public}s", callerName.c_str());
        return true;
    }
    IAM_LOGI("caller is not a hap or a native");
    return false;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS