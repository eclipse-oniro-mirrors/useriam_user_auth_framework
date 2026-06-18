/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "config_parser.h"

#include <filesystem>
#include <fstream>
#include <sstream>

#include "iam_logger.h"

#define LOG_FILE_ID LOG_FILE_CONFIG_PARSER
#define LOG_TAG "USER_AUTH_COMMON"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
bool ConfigParser::Load(const std::string &configPath)
{
    std::filesystem::path fsPath(configPath);
    std::error_code ec;
    std::filesystem::path canonicalPath = std::filesystem::canonical(fsPath, ec);
    if (ec) {
        IAM_LOGE("Failed to get canonical path: %{public}s, error: %{public}s", configPath.c_str(),
            ec.message().c_str());
        return false;
    }

    std::ifstream file(canonicalPath);
    if (!file.is_open()) {
        IAM_LOGE("Failed to open config file: %{public}s", canonicalPath.string().c_str());
        return false;
    }

    const std::filesystem::path allowedBasePath("/system/etc/useriam");
    if (canonicalPath.string().find(allowedBasePath.string()) != 0) {
        IAM_LOGE("Config file path not allowed: %{public}s", canonicalPath.string().c_str());
        return false;
    }

    try {
        std::stringstream buffer;
        buffer << file.rdbuf();
        configJson_ = nlohmann::json::parse(buffer.str());
        isLoaded_ = true;
        return true;
    } catch (const std::exception &e) {
        IAM_LOGE("Failed to parse config file: %{public}s, error: %{public}s", canonicalPath.string().c_str(),
            e.what());
        return false;
    }
}

std::string ConfigParser::Get(const std::string &key, const std::string &defaultValue) const
{
    if (!isLoaded_) {
        IAM_LOGE("Config file not loaded");
        return defaultValue;
    }

    try {
        if (!configJson_.contains(key)) {
            return defaultValue;
        }

        if (!configJson_[key].is_string()) {
            IAM_LOGE("Config value is not string type for key: %{public}s", key.c_str());
            return defaultValue;
        }

        return configJson_[key].get<std::string>();
    } catch (const std::exception &e) {
        IAM_LOGE("Failed to get config value for key: %{public}s, error: %{public}s", key.c_str(), e.what());
        return defaultValue;
    }
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS