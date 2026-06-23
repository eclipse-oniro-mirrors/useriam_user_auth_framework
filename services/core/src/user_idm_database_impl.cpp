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

#include "user_idm_database_impl.h"

#include "securec.h"

#include "attributes.h"
#include "enrolled_info_impl.h"
#include "hdi_wrapper.h"
#include "iam_logger.h"
#include "iam_para2str.h"
#include "iam_ptr.h"
#include "iam_hitrace_helper.h"
#include "iam_common_defines.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_IDM_DATABASE_IMPL

namespace OHOS {
namespace UserIam {
namespace UserAuth {
int32_t UserIdmDatabaseImpl::GetSecUserInfo(int32_t userId, std::shared_ptr<SecureUserInfoInterface> &secUserInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }

    std::vector<HdiEnrolledInfo> enrolledInfoVector;
    uint64_t secureUid = 0;
    int32_t pinSubType;
    int32_t ret = hdi->GetUserInfo(userId, secureUid, pinSubType, enrolledInfoVector);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetSecureInfo failed, error code : %{public}d", ret);
        return GENERAL_ERROR;
    }
    
    if (enrolledInfoVector.size() == 0) {
        IAM_LOGE("secUserInfo not found");
        return NOT_ENROLLED;
    }

    std::vector<std::shared_ptr<EnrolledInfoInterface>> infoRet;
    infoRet.reserve(enrolledInfoVector.size());

    for (auto const &info : enrolledInfoVector) {
        auto enrolledInfo = Common::MakeShared<EnrolledInfoImpl>(userId, info);
        if (enrolledInfo == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        infoRet.emplace_back(enrolledInfo);
    }
    secUserInfo = Common::MakeShared<SecureUserInfoImpl>(userId, secureUid, infoRet);
    if (secUserInfo == nullptr) {
        IAM_LOGE("bad alloc");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::GetCredentialInfo(int32_t userId, AuthType authType,
    std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    int32_t ret = hdi->GetCredential(userId, static_cast<HdiAuthType>(authType), hdiInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetCredential fail, userId:%{public}d, authType:%{public}d, ret:%{public}d", userId, authType, ret);
        return ret;
    }
    credInfos.reserve(hdiInfos.size());
    for (const auto &hdiInfo : hdiInfos) {
        auto info = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
        if (info == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(info);
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::DeleteUser(int32_t userId, const std::vector<uint8_t> &authToken,
    std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos, std::vector<uint8_t> &rootSecret)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    IamHitraceHelper traceHelper("hdi DeleteUser");
    int32_t ret = hdi->DeleteUser(userId, authToken, hdiInfos, rootSecret);
    if (ret != HDF_SUCCESS) {
        HILOG_COMM_ERROR("failed to delete user, error code : %{public}d, userId: %{public}d", ret, userId);
        return ret;
    }

    for (const auto &hdiInfo : hdiInfos) {
        auto infoRet = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
        if (infoRet == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(infoRet);
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::DeleteUserEnforce(int32_t userId,
    std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    IamHitraceHelper traceHelper("hdi EnforceDeleteUser");
    int32_t ret = hdi->EnforceDeleteUser(userId, hdiInfos);
    if (ret != HDF_SUCCESS) {
        HILOG_COMM_ERROR("failed to enforce delete user, error code : %{public}d, userId: %{public}d",
            ret, userId);
        return ret;
    }

    for (const auto &hdiInfo : hdiInfos) {
        auto infoRet = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
        if (infoRet == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(infoRet);
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::GetAllExtUserInfo(std::vector<std::shared_ptr<UserInfoInterface>> &userInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return INVALID_HDI_INTERFACE;
    }

    std::vector<ExtUserInfo> hdiUserInfos;
    int32_t ret = hdi->GetAllExtUserInfo(hdiUserInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetAllExtUserInfo failed, error code :%{public}d", ret);
        return ret;
    }

    for (const auto &iter : hdiUserInfos) {
        auto userInfo = Common::MakeShared<UserInfoImpl>(iter.userId, iter.userInfo);
        if (userInfo == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        userInfos.emplace_back(userInfo);
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::GetCredentialInfoById(uint64_t credentialId,
    std::shared_ptr<CredentialInfoInterface> &credInfo)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }

    HdiCredentialInfo hdiInfo;
    int32_t ret = hdi->GetCredentialById(credentialId, hdiInfo);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("GetCredentialById failed, error code : %{public}d", ret);
        return ret;
    }

    credInfo = Common::MakeShared<CredentialInfoImpl>(0, hdiInfo);
    if (credInfo == nullptr) {
        IAM_LOGE("bad alloc");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

int32_t UserIdmDatabaseImpl::ClearUnavailableCredential(int32_t userId,
    std::vector<std::shared_ptr<CredentialInfoInterface>> &credInfos)
{
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("bad hdi");
        return GENERAL_ERROR;
    }

    std::vector<HdiCredentialInfo> hdiInfos;
    std::vector<int32_t> userIds;
    userIds.push_back(userId);
    int32_t ret = hdi->ClearUnavailableCredential(userIds, hdiInfos);
    if (ret != HDF_SUCCESS) {
        IAM_LOGE("ClearUnavailableCredential failed, error code : %{public}d", ret);
        return ret;
    }

    for (const auto &hdiInfo : hdiInfos) {
        auto infoRet = Common::MakeShared<CredentialInfoImpl>(userId, hdiInfo);
        if (infoRet == nullptr) {
            IAM_LOGE("bad alloc");
            return GENERAL_ERROR;
        }
        credInfos.emplace_back(infoRet);
    }

    return SUCCESS;
}

UserIdmDatabase &UserIdmDatabase::Instance()
{
    return UserIdmDatabaseImpl::GetInstance();
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS