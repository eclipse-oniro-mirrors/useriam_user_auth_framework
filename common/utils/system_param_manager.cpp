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

#include "system_param_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SYSTEM_PARAM_MANAGER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
void OnParamChg(const char *key, const char *value, void *context)
{
    IF_FALSE_LOGE_AND_RETURN(key != nullptr);
    IF_FALSE_LOGE_AND_RETURN(value != nullptr);
    SystemParamManager::GetInstance().OnParamChange(std::string(key), std::string(value));
}
} // namespace

SystemParamManager &SystemParamManager::GetInstance()
{
    static SystemParamManager instance;
    return instance;
}

std::string SystemParamManager::GetParam(const std::string &key, const std::string &defaultValue)
{
    constexpr uint32_t maxValueLen = 128;
    char valueBuffer[maxValueLen] = { 0 };
    int32_t ret = GetParameter(key.c_str(), defaultValue.c_str(), valueBuffer, maxValueLen);
    if (ret < 0) {
        IAM_LOGE("get param failed, key %{public}s, ret %{public}d, use default value %{public}s", key.c_str(), ret,
            defaultValue.c_str());
        return defaultValue;
    }
    IAM_LOGI("get param key %{public}s value %{public}s", key.c_str(), valueBuffer);
    return std::string(valueBuffer);
}

void SystemParamManager::SetParam(const std::string &key, const std::string &value)
{
    std::string currentValue = GetParam(key, "");
    IAM_LOGI("set parameter: %{public}s, current value: %{public}s, value: %{public}s", key.c_str(),
        currentValue.c_str(), value.c_str());
    if (currentValue != value) {
        int32_t ret = SetParameter(key.c_str(), value.c_str());
        IF_FALSE_LOGE_AND_RETURN(ret == 0);
    }
}

void SystemParamManager::SetParamTwice(const std::string &key, const std::string &value1, const std::string &value2)
{
    std::string currentValue = GetParam(key, "");
    IAM_LOGI("set parameter: %{public}s, current value: %{public}s, value1: %{public}s, value2: %{public}s",
        key.c_str(), currentValue.c_str(), value1.c_str(), value2.c_str());
    if (currentValue != value1) {
        int32_t ret1 = SetParameter(key.c_str(), value1.c_str());
        IF_FALSE_LOGE_AND_RETURN(ret1 == 0);
    }
    int32_t ret2 = SetParameter(key.c_str(), value2.c_str());
    IF_FALSE_LOGE_AND_RETURN(ret2 == 0);
}

void SystemParamManager::WatchParam(const std::string &key, SystemParamCallback callback)
{
    IF_FALSE_LOGE_AND_RETURN(callback != nullptr);

    std::lock_guard<std::recursive_mutex> lock(mutex_);
    bool alreadyWatched = std::find_if(keyCallbackVec_.begin(), keyCallbackVec_.end(),
        [&key](const auto &item) { return item.first == key; }) != keyCallbackVec_.end();
    if (!alreadyWatched) {
        int32_t ret = WatchParameter(key.c_str(), OnParamChg, nullptr);
        IF_FALSE_LOGE_AND_RETURN(ret == 0);
    }

    bool hasSameCallback =
        std::find_if(keyCallbackVec_.begin(), keyCallbackVec_.end(), [&key, &callback](const auto &item) {
            return item.first == key && item.second == callback;
        }) != keyCallbackVec_.end();
    if (hasSameCallback) {
        IAM_LOGE("key %{public}s already watched with same callback", key.c_str());
        return;
    }
    keyCallbackVec_.push_back(std::make_pair(key, callback));
    IAM_LOGI("watch key %{public}s", key.c_str());
}

void SystemParamManager::OnParamChange(const std::string &key, const std::string &value)
{
    IAM_LOGI("on param change, key %{public}s, value %{public}s", key.c_str(), value.c_str());
    std::vector<std::pair<std::string, SystemParamCallback>> keyCallbackVec;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        keyCallbackVec = keyCallbackVec_;
    }

    for (const auto &item : keyCallbackVec) {
        if (item.first == key && item.second != nullptr) {
            item.second(value);
        }
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS