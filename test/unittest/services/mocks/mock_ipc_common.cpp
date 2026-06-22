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

#include "mock_ipc_common.h"

#include "iam_logger.h"
#ifdef HAS_OS_ACCOUNT_PART
#include "os_account_manager.h"
#endif // HAS_OS_ACCOUNT_PART
#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_IPC_COMMON

namespace {
    const uint32_t TEST_USER_ID = 548781;
    const std::string TEST_CALLER_BUNDLE_NAME = "com.ohos.useriam.authwidgettest";
}

namespace OHOS {
namespace UserIam {
namespace UserAuth {
std::set<Permission> IpcCommon::permSet_;
bool IpcCommon::isSetTokenId_ = false;
uint32_t IpcCommon::tokenId_ = 0;
bool IpcCommon::skipFlag_ = false;
bool IpcCommon::skipCallerFlag_ = false;
bool IpcCommon::skipAccountVerifiedFlag_ = false;
bool IpcCommon::skipActiveUserIdFlag_ = false;

int32_t IpcCommon::GetCallingUserId(IPCObjectStub &stub, int32_t &userId)
{
    if (userId != INVALID_USER_ID || skipFlag_) {
        return FAIL;
    }
    userId = TEST_USER_ID;
    return SUCCESS;
}

int32_t IpcCommon::GetActiveUserId(std::optional<int32_t> &userId)
{
    if (skipActiveUserIdFlag_) {
        return GENERAL_ERROR;
    }
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
    if (skipCallerFlag_) {
        return GENERAL_ERROR;
    }
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

int32_t IpcCommon::GetUserTypeByUserId(int32_t userId, int32_t &userType)
{
    userType = 0;
    return SUCCESS;
}

// for unittest only
bool IpcCommon::CheckPermission(IPCObjectStub &stub, Permission permission)
{
    return permSet_.find(permission) != permSet_.end();
}

uint32_t IpcCommon::GetAccessTokenId(IPCObjectStub &stub)
{
    if (isSetTokenId_) {
        return tokenId_;
    }
    tokenId_ = stub.GetFirstTokenID();
    if (tokenId_ == 0) {
        tokenId_ = stub.GetCallingTokenID();
    }
    return tokenId_;
}

void IpcCommon::SetSkipCallerFlag(bool isSkip)
{
    skipCallerFlag_ = isSkip;
}

void IpcCommon::SetSkipAccountVerifiedFlag(bool isSkip)
{
    skipAccountVerifiedFlag_ = isSkip;
}

void IpcCommon::SetSkipActiveUserIdCallerFlag(bool isSkip)
{
    skipActiveUserIdFlag_ = isSkip;
}

void IpcCommon::SetAccessTokenId(uint32_t tokenId, bool isSetTokenId)
{
    tokenId_ =  tokenId;
    isSetTokenId_ = isSetTokenId;
}

void IpcCommon::AddPermission(Permission perm)
{
    permSet_.insert(perm);
}

void IpcCommon::DeleteAllPermission()
{
    permSet_.clear();
}

uint32_t IpcCommon::GetTokenId(IPCObjectStub &stub)
{
    uint32_t tokenId = stub.GetCallingTokenID();
    IAM_LOGI("get tokenId: %{public}d", tokenId);
    return tokenId;
}

void IpcCommon::SetSkipUserFlag(bool isSkip)
{
    skipFlag_ = isSkip;
}

bool IpcCommon::GetCallerName(IPCObjectStub &stub, std::string &callerName, int32_t &callerType)
{
    if (skipCallerFlag_) {
        return false;
    }
    callerName = "";
    callerType = 0;
    return true;
}

bool IpcCommon::GetCallingAppID(IPCObjectStub &stub, std::string &callingAppID)
{
    callingAppID = "";
    return true;
}

bool IpcCommon::CheckForegroundApplication(const std::string &bundleName)
{
    if (skipFlag_) {
        return false;
    }
    return true;
}

bool IpcCommon::IsOsAccountVerified(int32_t userId)
{
    if (skipAccountVerifiedFlag_) {
        return false;
    }
    return true;
}

int32_t IpcCommon::GetDirectCallerType(IPCObjectStub &stub)
{
    return 0;
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS