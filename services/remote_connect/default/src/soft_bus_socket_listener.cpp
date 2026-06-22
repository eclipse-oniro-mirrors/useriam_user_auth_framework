/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "soft_bus_socket_listener.h"

#include "soft_bus_manager.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_SOFT_BUS_SOCKET_LISTENER

namespace OHOS {
namespace UserIam {
namespace UserAuth {
namespace {
constexpr uint32_t MAX_DATA_LEN = 4096;
}

bool SoftBusSocketListener::OnNegotiate(int32_t socketId, PeerSocketInfo info)
{
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return false;
    }

    if (info.pkgName == nullptr) {
        IAM_LOGE("pkgName is null.");
        return false;
    }

    if (std::string(info.pkgName) != USER_AUTH_PACKAGE_NAME) {
        IAM_LOGE("unexpected package name %{public}s.", info.pkgName);
        return false;
    }

    return true;
}

void SoftBusSocketListener::OnBind(int32_t socketId, PeerSocketInfo info)
{
    IAM_LOGI("socket id is %{public}d.", socketId);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    if (info.pkgName == nullptr) {
        IAM_LOGE("pkgName is null.");
        return;
    }

    if (std::string(info.pkgName) != USER_AUTH_PACKAGE_NAME) {
        IAM_LOGE("unexpected package name %{public}s.", info.pkgName);
        return;
    }

    SoftBusManager::GetInstance().OnBind(socketId, info);
}

void SoftBusSocketListener::OnShutdown(int32_t socketId, ShutdownReason reason)
{
    IAM_LOGI("socket id %{public}d shutdown because %{public}d.", socketId, reason);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    SoftBusManager::GetInstance().OnShutdown(socketId, reason);
}

void SoftBusSocketListener::OnClientBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}u.", socketId, dataLen);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }

    if (dataLen > MAX_DATA_LEN) {
        IAM_LOGE("exceed max data length");
        return;
    }

    SoftBusManager::GetInstance().OnClientBytes(socketId, data, dataLen);
}

void SoftBusSocketListener::OnServerBytes(int32_t socketId, const void *data, uint32_t dataLen)
{
    IAM_LOGI("socket fd %{public}d, recv len %{public}u.", socketId, dataLen);
    if (socketId <= INVALID_SOCKET_ID) {
        IAM_LOGE("socket id invalid.");
        return;
    }
    if (dataLen > MAX_DATA_LEN) {
        IAM_LOGE("exceed max data length");
        return;
    }
    SoftBusManager::GetInstance().OnServerBytes(socketId, data, dataLen);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS