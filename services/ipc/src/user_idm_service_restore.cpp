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

#include "user_idm_service.h"

#include <fcntl.h>
#include <future>
#include <sys/stat.h>
#include <unistd.h>

#include "unique_fd.h"

#include "accesstoken_kit.h"
#include "device_manager_util.h"
#include "user_auth_engine.h"
#include "iam_common_defines.h"
#include "iam_check.h"
#include "iam_defines.h"
#include "iam_scope_guard.h"
#include "iam_logger.h"
#include "iam_check.h"
#include "ipc_common.h"
#include "nlohmann/json.hpp"
#include "resource_node_utils.h"
#include "user_idm_database.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_USER_IDM_SERVICE

namespace OHOS {
namespace UserIam {
namespace UserAuth {
const std::string CLONE_DATA_TEMP_PATH = "/data/local/tmp";
const std::string JSON_KEY_TYPE = "type";
const std::string JSON_KEY_DETAIL = "detail";
const std::string JSON_VALUE_USER_ID = "userId";
const std::string JSON_VALUE_TOKEN = "token";
const std::string JSON_VALUE_UDID = "udid";
const std::string EXTENSION_BACKUP = "backup";
const std::string EXTENSION_RESTORE = "restore";
constexpr int32_t RESTORE_ENROLL_TIMEOUT_MS = 60000;
constexpr uint32_t EXECUTOR_MSG_LEN = 1024;
const std::vector<AuthType> SUPPORTED_CLONE_AUTH_TYPES = {AuthType::PRIVATE_PIN};

Attributes::AttributeKey GetCloneAttrKey(AuthType authType)
{
    switch (authType) {
        case AuthType::PRIVATE_PIN:
            return Attributes::ATTR_CLONE_PRIVATE_PIN_INFO;
        default:
            return Attributes::ATTR_ROOT;
    }
}

class RestoreEnrollCallback : public IIamCallback, public NoCopyable {
public:
    explicit RestoreEnrollCallback(std::shared_ptr<std::promise<int32_t>> promise) : promise_(promise) {}
    ~RestoreEnrollCallback() override = default;
    int32_t OnResult(int32_t resultCode, const std::vector<uint8_t> &extraInfo) override
    {
        IAM_LOGI("restore enroll OnResult, resultCode:%{public}d", resultCode);
        if (promise_ != nullptr) {
            promise_->set_value(resultCode);
        }
        return SUCCESS;
    }
    int32_t OnAcquireInfo(int32_t module, int32_t acquireInfo, const std::vector<uint8_t> &extraInfo) override
    {
        return SUCCESS;
    }
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
private:
    std::shared_ptr<std::promise<int32_t>> promise_;
};

int32_t UserIdmService::OnExtension(const std::string& extension, MessageParcel& data, MessageParcel& reply)
{
    if (!IpcCommon::CheckPermission(*this, MANAGE_USER_IDM_PERMISSION)) {
        IAM_LOGE("failed to check permission");
        reply.WriteInt32(CHECK_PERMISSION_FAILED);
        return CHECK_PERMISSION_FAILED;
    }

    int ret = GENERAL_ERROR;
    if (extension == EXTENSION_BACKUP) {
        ret = OnBackup(data, reply);
    } else if (extension == EXTENSION_RESTORE) {
        ret = OnRestore(data, reply);
    }
    reply.WriteInt32(ret);
    return ret;
}

int32_t UserIdmService::OnBackup(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("Idm OnBackup started.");
    int32_t userId = INVALID_USER_ID;
    std::vector<uint8_t> peerUdid = {};
    std::vector<uint8_t> token = {};
    int32_t ret = ParseCloneInfo(data, userId, peerUdid, token);
    if (ret != SUCCESS) {
        IAM_LOGE("ParseCloneInfo fail, ret:%{public}d", ret);
        return ret;
    }

    EngUserAuthTokenPlain tokenPlain = {};
    EngUserAuthTokenExtraInfo extraInfo = {};
    const uint32_t TEN_MINUTE = 10 * 60 * 1000;
    int32_t result = GetUserAuthEngine().VerifyAuthToken(userId, token, TEN_MINUTE, tokenPlain, extraInfo);
    if (result != SUCCESS) {
        IAM_LOGE("VerifyAuthToken failed, result:%{public}d", result);
        return result;
    }

    Attributes attrIn = BuildBackupExtraIn(userId, peerUdid, extraInfo.executorMsg);
    Attributes attrOut = {};
    for (auto authType : SUPPORTED_CLONE_AUTH_TYPES) {
        ret = OnBackupInner(userId, authType, attrIn, attrOut);
        if (ret != SUCCESS) {
            IAM_LOGE("OnBackupInner fail, ret:%{public}d", ret);
            return ret;
        }
    }

    ret = WriteCloneDataToFile(attrOut.Serialize(), reply);
    if (ret != SUCCESS) {
        IAM_LOGE("WriteCloneDataToFile fail, ret:%{public}d", ret);
    }
    IAM_LOGI("Idm onBackup end extraOut:%{public}zu", attrOut.Serialize().size());
    return ret;
}

int32_t UserIdmService::OnBackupInner(int32_t userId, AuthType authType, const Attributes &attrIn,
    Attributes &attrOut)
{
    std::vector<std::shared_ptr<CredentialInfoInterface>> credentialInfos = {};
    int32_t ret = UserIdmDatabase::Instance().GetCredentialInfo(userId, authType, credentialInfos);
    if (ret != SUCCESS || credentialInfos.empty()) {
        IAM_LOGI("not enrolled, OnBackup no need to execute, ret:%{public}d", ret);
        return SUCCESS;
    }

    std::vector<uint8_t> executorOut = {};
    ret = ResourceNodeUtils::SendCommandToExecutor(authType, ExecutorRole::ALL_IN_ONE,
        static_cast<uint32_t>(PROPERTY_MODE_BACK_UP), attrIn.Serialize(), executorOut);
    if (ret != SUCCESS) {
        IAM_LOGE("SendCommandToExecutor fail, ret:%{public}d", ret);
        return ret;
    }

    Attributes::AttributeKey cloneKey = GetCloneAttrKey(authType);
    if (cloneKey == Attributes::ATTR_ROOT) {
        IAM_LOGE("unsupported authType for clone");
        return GENERAL_ERROR;
    }
    if (!attrOut.SetUint8ArrayValue(cloneKey, executorOut)) {
        IAM_LOGE("set clone attr fail");
        return GENERAL_ERROR;
    }
    return SUCCESS;
}

Attributes UserIdmService::BuildBackupExtraIn(int32_t userId, const std::vector<uint8_t> &peerUdid,
    const std::vector<uint8_t> &executorMsg)
{
    Attributes backupAttr = {};
    if (executorMsg.size() > EXECUTOR_MSG_LEN) {
        IAM_LOGE("executorMsg too long, size:%{public}zu", executorMsg.size());
        return backupAttr;
    }
    if (!backupAttr.SetInt32Value(Attributes::ATTR_USER_ID, userId)) {
        IAM_LOGE("set ATTR_USER_ID fail");
        return backupAttr;
    }
    if (!backupAttr.SetUint8ArrayValue(Attributes::HAL_ATTR_PEER_UDID, peerUdid)) {
        IAM_LOGE("set HAL_ATTR_PEER_UDID fail");
        return backupAttr;
    }
    if (!backupAttr.SetUint8ArrayValue(Attributes::HAL_ATTR_FWK_MSG, executorMsg)) {
        IAM_LOGE("set HAL_ATTR_FWK_MSG fail");
        return backupAttr;
    }
    return backupAttr;
}

int32_t UserIdmService::ParseCloneInfo(MessageParcel &data, int32_t &userId,
    std::vector<uint8_t> &peerUdid, std::vector<uint8_t> &token)
{
    std::string jsonStr = data.ReadString();
    IF_FALSE_LOGE_AND_RETURN_VAL(nlohmann::json::accept(jsonStr), GENERAL_ERROR);
    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr, nullptr, false);
    IF_FALSE_LOGE_AND_RETURN_VAL(!jsonObj.is_discarded(), GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(jsonObj.is_array(), GENERAL_ERROR);

    for (const auto &item : jsonObj) {
        if (!item.is_object()) {
            continue;
        }
        if (item.find(JSON_KEY_TYPE) == item.end() || item.find(JSON_KEY_DETAIL) == item.end()) {
            continue;
        }
        if (!item[JSON_KEY_TYPE].is_string() || !item[JSON_KEY_DETAIL].is_string()) {
            continue;
        }
        std::string type = {};
        std::string detail = {};
        try {
            type = item[JSON_KEY_TYPE].get<std::string>();
            detail = item[JSON_KEY_DETAIL].get<std::string>();
        } catch (const std::exception &e) {
            IAM_LOGE("get json string failed: %{public}s", e.what());
            continue;
        }
        if (type == JSON_VALUE_USER_ID) {
            try {
                userId = std::stoi(detail);
            } catch (const std::exception &e) {
                IAM_LOGE("convert userId failed: %{public}s", e.what());
                return GENERAL_ERROR;
            }
        } else if (type == JSON_VALUE_UDID) {
            peerUdid.assign(detail.begin(), detail.end());
        } else if (type == JSON_VALUE_TOKEN) {
            token.assign(detail.begin(), detail.end());
        }
    }
    const uint32_t DEVICE_UDID_LEN = 64;
    IF_FALSE_LOGE_AND_RETURN_VAL(peerUdid.size() == DEVICE_UDID_LEN, GENERAL_ERROR);
    IF_FALSE_LOGE_AND_RETURN_VAL(userId != INVALID_USER_ID, GENERAL_ERROR);
    return SUCCESS;
}

int32_t UserIdmService::WriteCloneDataToFile(const std::vector<uint8_t> &backUpData, MessageParcel &reply)
{
    if (backUpData.empty()) {
        IAM_LOGI("backUpData is empty");
        return SUCCESS;
    }

    UniqueFd fd(open(CLONE_DATA_TEMP_PATH.c_str(), O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR));
    if (fd.Get() < 0) {
        IAM_LOGE("open backup file failed, errno: %{public}d", errno);
        return GENERAL_ERROR;
    }

    ssize_t written = 0;
    size_t remaining = backUpData.size();
    const uint8_t *data = backUpData.data();
    while (remaining > 0) {
        written = write(fd.Get(), data, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            IAM_LOGE("write failed, errno: %{public}d", errno);
            return GENERAL_ERROR;
        }
        data += written;
        remaining -= static_cast<size_t>(written);
    }

    if (lseek(fd.Get(), 0, SEEK_SET) != 0) {
        IAM_LOGE("lseek failed.");
        return GENERAL_ERROR;
    }

    if (!reply.WriteFileDescriptor(fd.Get())) {
        IAM_LOGE("OnBackup: reply write fail");
        return GENERAL_ERROR;
    }

    return SUCCESS;
}

int32_t UserIdmService::OnRestore(MessageParcel &data, MessageParcel &reply)
{
    IAM_LOGI("idm OnRestore start");
    std::vector<uint8_t> cloneData = {};
    int32_t ret = ReadCloneDataFromFile(data, cloneData, EXECUTOR_MSG_LEN);
    if (ret != SUCCESS) {
        IAM_LOGE("ReadCloneDataFromFile fail, ret:%{public}d", ret);
        return ret;
    }

    int32_t userId = INVALID_USER_ID;
    std::vector<uint8_t> peerUdid = {};
    std::vector<uint8_t> token = {};
    ret = ParseCloneInfo(data, userId, peerUdid, token);
    if (ret != SUCCESS) {
        IAM_LOGE("ParseCloneInfo fail, ret:%{public}d", ret);
        return ret;
    }

    Attributes outerAttr(cloneData);
    for (auto authType : SUPPORTED_CLONE_AUTH_TYPES) {
        Attributes::AttributeKey cloneKey = GetCloneAttrKey(authType);
        if (cloneKey == Attributes::ATTR_ROOT) {
            continue;
        }
        std::vector<uint8_t> innerData = {};
        if (!outerAttr.GetUint8ArrayValue(cloneKey, innerData)) {
            continue;
        }
        ret = OnRestoreInner(userId, authType, peerUdid, innerData);
        if (ret != SUCCESS) {
            IAM_LOGE("OnRestoreInner fail, ret:%{public}d", ret);
            return ret;
        }
    }

    IAM_LOGI("idm OnRestore end %{public}zu.", cloneData.size());
    return ret;
}

int32_t UserIdmService::OnRestoreInner(int32_t userId, AuthType authType,
    const std::vector<uint8_t> &peerUdid, const std::vector<uint8_t> &innerData)
{
    Attributes restoreAttr(innerData);
    if (!restoreAttr.SetInt32Value(Attributes::ATTR_USER_ID, userId)) {
        IAM_LOGE("set ATTR_USER_ID fail");
        return GENERAL_ERROR;
    }
    if (!restoreAttr.SetUint8ArrayValue(Attributes::HAL_ATTR_PEER_UDID, peerUdid)) {
        IAM_LOGE("set HAL_ATTR_PEER_UDID fail");
        return GENERAL_ERROR;
    }

    auto promise = std::make_shared<std::promise<int32_t>>();
    std::future<int32_t> future = promise->get_future();
    std::vector<uint8_t> restoreData = restoreAttr.Serialize();
    int32_t ret = StartRestoreEnroll(userId, authType, restoreData, promise);
    if (ret != SUCCESS) {
        IAM_LOGE("StartRestoreEnroll fail, ret:%{public}d", ret);
        CloseSession(userId);
        return ret;
    }
    ret = WaitForRestoreEnrollResult(userId, future);
    if (ret != SUCCESS) {
        IAM_LOGE("WaitForRestoreEnrollResult fail, ret:%{public}d", ret);
    }
    CloseSession(userId);
    return ret;
}

int32_t UserIdmService::StartRestoreEnroll(int32_t userId, AuthType authType, std::vector<uint8_t> &restoreData,
    std::shared_ptr<std::promise<int32_t>> promise)
{
    IAM_LOGI("StartRestoreEnroll %{public}zu", restoreData.size());
    sptr<IIamCallback> iamCallback(new (std::nothrow) RestoreEnrollCallback(promise));
    if (iamCallback == nullptr) {
        IAM_LOGE("failed to create restore enroll callback");
        return GENERAL_ERROR;
    }
    auto contextCallback = ContextCallback::NewInstance(iamCallback, TRACE_ADD_CREDENTIAL);
    if (contextCallback == nullptr) {
        IAM_LOGE("failed to construct context callback for restore enroll");
        return GENERAL_ERROR;
    }
    std::string callerName = "";
    int32_t callerType = Security::AccessToken::TOKEN_INVALID;
    static_cast<void>(IpcCommon::GetCallerName(*this, callerName, callerType));
    Enrollment::EnrollmentPara para = {};
    para.userId = userId;
    para.authType = authType;
    para.pinType = PinSubType::DEFAULT_PIN_SUB_TYPE;
    para.tokenId = IpcCommon::GetAccessTokenId(*this);
    para.isUpdate = false;
    para.sdkVersion = INNER_API_VERSION_10000;
    para.callerName = callerName;
    para.callerType = callerType;
    para.isRestore = true;
    para.restoreData = restoreData;
    Attributes extraInfo = {};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        std::vector<uint8_t> challenge = {};
        int32_t ret = GetUserAuthEngine().OpenSession(userId, challenge);
        if (ret != SUCCESS) {
            IAM_LOGE("failed to open session, error code:%{public}d", ret);
            return GENERAL_ERROR;
        }
        ret = StartEnroll(para, contextCallback, extraInfo, true);
        if (ret != SUCCESS) {
            return ret;
        }
    }
    return SUCCESS;
}

int32_t UserIdmService::WaitForRestoreEnrollResult(int32_t userId, std::future<int32_t> &future)
{
    std::future_status status = future.wait_for(std::chrono::milliseconds(RESTORE_ENROLL_TIMEOUT_MS));
    if (status != std::future_status::ready) {
        IAM_LOGE("restore enroll timeout");
        return GENERAL_ERROR;
    }
    int32_t result = future.get();
    IAM_LOGI("restore enroll result:%{public}d", result);
    return result;
}

int32_t UserIdmService::ReadCloneDataFromFile(MessageParcel &data, std::vector<uint8_t> &cloneData, int32_t maxLen)
{
    UniqueFd fd(data.ReadFileDescriptor());
    struct stat st = {};
    if (fstat(fd.Get(), &st) != 0 || st.st_size == 0) {
        IAM_LOGE("fstat failed, errno: %{public}d, st_size:%{public}ld", errno, st.st_size);
        return GENERAL_ERROR;
    }
    if (lseek(fd.Get(), 0, SEEK_SET) != 0) {
        IAM_LOGE("lseek to begin failed, errno: %{public}d", errno);
        return GENERAL_ERROR;
    }
    static const size_t RESTORE_BUFFER_SIZE = 1024;
    std::vector<uint8_t> buffer(RESTORE_BUFFER_SIZE);
    int32_t totalSize = 0;
    while (true) {
        ssize_t bytesRead = read(fd.Get(), buffer.data(), RESTORE_BUFFER_SIZE);
        if (bytesRead < 0) {
            if (errno == EINTR) {
                continue;
            }
            IAM_LOGE("read from fd fail, errno: %{public}d", errno);
            return GENERAL_ERROR;
        }
        if (bytesRead == 0) {
            IAM_LOGE("bytesRead is empty");
            break;
        }
        if (totalSize + bytesRead > maxLen) {
            IAM_LOGE("clone data exceeds max size");
            return GENERAL_ERROR;
        }
        cloneData.insert(cloneData.end(), buffer.begin(), buffer.begin() + bytesRead);
        totalSize += bytesRead;
    }
    IAM_LOGI("clone data len is %{public}zu", cloneData.size());
    return SUCCESS;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
