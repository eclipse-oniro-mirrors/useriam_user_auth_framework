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

#include "auth_widget_helper.h"

#include <cinttypes>
#include "securec.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "resource_node_pool.h"
#include "user_idm_database.h"
#include "widget_client.h"

#define LOG_FILE_ID LOG_FILE_AUTH_WIDGET_HELPER
#define LOG_TAG "USER_AUTH_SA"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

bool AuthWidgetHelper::InitWidgetContextParam(const AuthParamInner &authParam, std::vector<AuthType> &validType,
    const WidgetParamInner &widgetParam, ContextFactory::AuthWidgetContextPara &para)
{
    para.challenge = std::move(authParam.challenge);
    para.authTypeList = std::move(validType);
    para.atl = authParam.authTrustLevel;
    para.skipLockedBiometricAuth = authParam.skipLockedBiometricAuth;
    para.widgetParam = widgetParam;
    if (widgetParam.windowMode == WindowModeType::UNKNOWN_WINDOW_MODE) {
        para.widgetParam.windowMode = WindowModeType::DIALOG_BOX;
    }
    para.credentialIdList = authParam.credentialIdList;
    return true;
}

bool AuthWidgetHelper::GetAuthCredentialList(int32_t userId, const AuthType &authType,
    const std::vector<uint64_t> &credentialIdList,
    std::vector<std::shared_ptr<CredentialInfoInterface>> &credentialInfos)
{
    if (credentialIdList.empty()) {
        int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
        if (ret != SUCCESS) {
            IAM_LOGE("get credential fail, ret:%{public}d, userId:%{public}d, authType:%{public}d", ret,
                userId, authType);
            return false;
        }
        return true;
    }

    for (auto credId : credentialIdList) {
        std::shared_ptr<CredentialInfoInterface> credInfo;
        int32_t ret = UserIdmDatabase::Instance().GetCredentialInfoById(credId, credInfo);
        if (ret != SUCCESS) {
            IAM_LOGE("get GetCredentialInfoById fail, ret:%{public}d", ret);
            return false;
        }
        credentialInfos.push_back(credInfo);
    }
    return true;
}

bool AuthWidgetHelper::GetUserAuthProfile(int32_t userId, const AuthType &authType,
    ContextFactory::AuthProfile &profile, std::vector<uint64_t> credentialIdList)
{
    Attributes values;
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos;
    if (!GetAuthCredentialList(userId, authType, credentialIdList, credentialInfos)) {
        IAM_LOGE("GetAuthCredentialList fail");
        return false;
    }
    if (credentialInfos.empty() || credentialInfos[0] == nullptr) {
        IAM_LOGE("user %{public}d has no credential type %{public}d", userId, authType);
        return true;
    }
    auto resourceNode = ResourceNodePool::Instance().Select(credentialInfos[0]->GetExecutorIndex()).lock();
    if (resourceNode == nullptr) {
        IAM_LOGE("resourceNode is nullptr");
        return false;
    }
    std::vector<uint64_t> templateIds;
    templateIds.reserve(credentialInfos.size());
    for (auto &info : credentialInfos) {
        if (info != nullptr) {
            templateIds.push_back(info->GetTemplateId());
        }
    }
    std::vector<uint32_t> uint32Keys = {Attributes::ATTR_REMAIN_TIMES, Attributes::ATTR_FREEZING_TIME};
    if (authType == AuthType::PIN || authType == AuthType::PRIVATE_PIN) {
        uint32Keys.push_back(Attributes::ATTR_PIN_SUB_TYPE);
    } else if (authType == AuthType::FINGERPRINT) {
        uint32Keys.push_back(Attributes::ATTR_SENSOR_INFO);
    } else if (authType == AuthType::FACE) {
        uint32Keys.push_back(Attributes::ATTR_CAMERA_STATUS);
    }
    Attributes attr;
    attr.SetInt32Value(Attributes::ATTR_AUTH_TYPE, authType);
    attr.SetUint32Value(Attributes::ATTR_PROPERTY_MODE, PROPERTY_MODE_GET);
    attr.SetUint64ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, templateIds);
    attr.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, uint32Keys);
    int32_t result = resourceNode->GetProperty(attr, values);
    if (result != SUCCESS) {
        IAM_LOGE("failed to get property, result = %{public}d", result);
        return false;
    }
    return ParseAttributes(values, authType, profile);
}

bool AuthWidgetHelper::ParseAttributes(const Attributes &values, const AuthType &authType,
    ContextFactory::AuthProfile &profile)
{
    if (authType == AuthType::PIN || authType == AuthType::PRIVATE_PIN) {
        if (!values.GetInt32Value(Attributes::ATTR_PIN_SUB_TYPE, profile.pinSubType)) {
            IAM_LOGE("get ATTR_PIN_SUB_TYPE failed");
            return false;
        }
    }
    if (authType == AuthType::FINGERPRINT && (!values.GetStringValue(Attributes::ATTR_SENSOR_INFO,
        profile.sensorInfo))) {
        IAM_LOGE("get ATTR_SENSOR_INFO failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, profile.remainTimes)) {
        IAM_LOGE("get ATTR_REMAIN_TIMES failed");
        return false;
    }
    if (!values.GetInt32Value(Attributes::ATTR_FREEZING_TIME, profile.freezingTime)) {
        IAM_LOGE("get ATTR_FREEZING_TIME failed");
        return false;
    }
    if (authType == AuthType::FACE && !values.GetUint32Value(Attributes::ATTR_CAMERA_STATUS, profile.cameraStatus)) {
        IAM_LOGE("get ATTR_CAMERA_STATUS failed");
        return false;
    }
    return true;
}

int32_t AuthWidgetHelper::CheckValidSolution(int32_t userId,
    const std::vector<AuthType> &authTypeList, const AuthTrustLevel &atl, std::vector<AuthType> &validTypeList)
{
    IAM_LOGI("start userId:%{public}d atl:%{public}u typeSize:%{public}zu", userId, atl, authTypeList.size());
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }
    std::vector<int32_t> inputAuthType;
    std::vector<int32_t> validTypes;
    uint32_t inputAtl = atl;
    for (auto &type : authTypeList) {
        inputAuthType.emplace_back(static_cast<int32_t>(type));
    }
    int32_t result = hdi->GetValidSolution(userId, inputAuthType, inputAtl, validTypes);
    if (result != SUCCESS) {
        IAM_LOGE("GetValidSolution failed result:%{public}d userId:%{public}d", result, userId);
        return result;
    }
    validTypeList.clear();
    for (auto &type : validTypes) {
        IAM_LOGI("get valid authType:%{public}d", type);
        validTypeList.emplace_back(static_cast<AuthType>(type));
    }
    return result;
}

int32_t AuthWidgetHelper::SetReuseUnlockResult(int32_t apiVersion, const HdiReuseUnlockInfo &info,
    Attributes &extraInfo)
{
    bool setSignatureResult = extraInfo.SetUint8ArrayValue(Attributes::ATTR_SIGNATURE, info.token);
    IF_FALSE_LOGE_AND_RETURN_VAL(setSignatureResult == true, GENERAL_ERROR);
    bool setAuthTypeResult = extraInfo.SetInt32Value(Attributes::ATTR_AUTH_TYPE,
        static_cast<int32_t>(info.authType));
    IF_FALSE_LOGE_AND_RETURN_VAL(setAuthTypeResult == true, GENERAL_ERROR);
    bool setResultCodeRet = extraInfo.SetInt32Value(Attributes::ATTR_RESULT_CODE, SUCCESS);
    IF_FALSE_LOGE_AND_RETURN_VAL(setResultCodeRet == true, GENERAL_ERROR);
    uint64_t credentialDigest = info.enrolledState.credentialDigest;
    if (apiVersion < INNER_API_VERSION_10000) {
        credentialDigest = info.enrolledState.credentialDigest & UINT16_MAX;
    }
    bool setCredentialDigestRet = extraInfo.SetUint64Value(Attributes::ATTR_CREDENTIAL_DIGEST, credentialDigest);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialDigestRet == true, GENERAL_ERROR);
    bool setCredentialCountRet = extraInfo.SetUint16Value(Attributes::ATTR_CREDENTIAL_COUNT,
        info.enrolledState.credentialCount);
    IF_FALSE_LOGE_AND_RETURN_VAL(setCredentialCountRet == true, GENERAL_ERROR);
    return SUCCESS;
}

int32_t AuthWidgetHelper::QueryReusableAuthResult(const int32_t userId, const AuthParamInner &authParam,
    HdiReuseUnlockInfo &reuseResultInfo)
{
    IAM_LOGI("start userId:%{public}d, reuseMode:%{public}u, reuseDuration: %{public}" PRIu64 ".",
        userId, authParam.reuseUnlockResult.reuseMode, authParam.reuseUnlockResult.reuseDuration);
    if (!authParam.reuseUnlockResult.isReuse || authParam.reuseUnlockResult.reuseDuration == 0 ||
        authParam.reuseUnlockResult.reuseDuration > MAX_ALLOWABLE_REUSE_DURATION ||
        (authParam.reuseUnlockResult.reuseMode != AUTH_TYPE_RELEVANT &&
        authParam.reuseUnlockResult.reuseMode != AUTH_TYPE_IRRELEVANT &&
        authParam.reuseUnlockResult.reuseMode != CALLER_IRRELEVANT_AUTH_TYPE_RELEVANT &&
        authParam.reuseUnlockResult.reuseMode != CALLER_IRRELEVANT_AUTH_TYPE_IRRELEVANT)) {
        IAM_LOGE("CheckReuseUnlockResult invalid param");
        return INVALID_PARAMETERS;
    }
    auto hdi = HdiWrapper::GetHdiInstance();
    if (hdi == nullptr) {
        IAM_LOGE("hdi interface is nullptr");
        return GENERAL_ERROR;
    }

    HdiReuseUnlockParam unlockParam = {};
    unlockParam.baseParam.userId = userId;
    unlockParam.baseParam.authTrustLevel = authParam.authTrustLevel;
    for (auto &type : authParam.authTypes) {
        unlockParam.authTypes.emplace_back(static_cast<HdiAuthType>(type));
    }
    unlockParam.baseParam.challenge = authParam.challenge;
    unlockParam.reuseUnlockResultMode = authParam.reuseUnlockResult.reuseMode;
    unlockParam.reuseUnlockResultDuration = authParam.reuseUnlockResult.reuseDuration;

    return hdi->CheckReuseUnlockResult(unlockParam, reuseResultInfo);
}

int32_t AuthWidgetHelper::CheckReuseUnlockResult(const ContextFactory::AuthWidgetContextPara &para,
    const AuthParamInner &authParam, Attributes &extraInfo)
{
    IAM_LOGI("start userId:%{public}d, reuseMode:%{public}u, reuseDuration: %{public}" PRIu64 ".",
        para.userId, authParam.reuseUnlockResult.reuseMode, authParam.reuseUnlockResult.reuseDuration);
    HdiReuseUnlockInfo reuseResultInfo = {};
    int32_t result = QueryReusableAuthResult(para.userId, authParam, reuseResultInfo);
    if (result != SUCCESS) {
        IAM_LOGE("QueryReusableAuthResult failed result:%{public}d userId:%{public}d", result, para.userId);
        return result;
    }

    return SetReuseUnlockResult(para.sdkVersion, reuseResultInfo, extraInfo);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS