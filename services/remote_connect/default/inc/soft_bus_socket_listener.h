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

#ifndef IAM_SOFT_BUS_SOCKET_LISTENER_H
#define IAM_SOFT_BUS_SOCKET_LISTENER_H

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <cstdint>
#include "socket.h"

#include "iam_logger.h"
#include "iam_common_defines.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class SoftBusSocketListener final {
public:
    static void OnBind(int32_t socketId, PeerSocketInfo info);
    static void OnShutdown(int32_t socketId, ShutdownReason reason);
    static void OnQos(int32_t socketId, QoSEvent eventId, const QosTV *qos, uint32_t qosCount) {};
    static void OnClientBytes(int32_t socketId, const void *data, uint32_t dataLen);
    static void OnServerBytes(int32_t socketId, const void *data, uint32_t dataLen);
    static bool OnNegotiate(int32_t socketId, PeerSocketInfo info);
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // IAM_SOFT_BUS_SOCKET_LISTENER_H