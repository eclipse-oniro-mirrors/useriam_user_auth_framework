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

#ifndef VAB_UPDATE_BOOT_LISTENER_H
#define VAB_UPDATE_BOOT_LISTENER_H

#include <functional>
#include <mutex>
#include <optional>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class VabUpdateBootListener : public std::enable_shared_from_this<VabUpdateBootListener> {
public:
    using VabUpdateBootCallback = std::function<void()>;

    VabUpdateBootListener(VabUpdateBootCallback cb);
    ~VabUpdateBootListener();

    static std::shared_ptr<VabUpdateBootListener> Start(VabUpdateBootCallback cb);

    void OnVabUpdateBoot();

private:
    void StartListen();
    void HandleBootEvent();

    std::recursive_mutex mutex_;
    VabUpdateBootCallback callback_;

    std::optional<uint32_t> vabUpdateBootTimerId_;
    int32_t vabUpdateBootTimerCount_ = 0;
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
#endif // VAB_UPDATE_BOOT_LISTENER_H
