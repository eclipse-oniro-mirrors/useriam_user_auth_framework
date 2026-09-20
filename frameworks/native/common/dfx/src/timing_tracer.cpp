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

#include "timing_tracer.h"

#include <chrono>
#include <sstream>

namespace OHOS {
namespace UserIam {
namespace UserAuth {

uint64_t TimingTracer::Now() const
{
    auto now = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return static_cast<uint64_t>(duration.count());
}

void TimingTracer::Start()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    startMs_ = Now();
    endMs_.reset();
    points_.clear();
    waitMs_ = 0;
    inWait_ = false;
    waitEnterMs_ = 0;
}

void TimingTracer::CloseWaitIfNeeded(uint64_t now)
{
    if (inWait_) {
        uint32_t delta = SafeSubToU32(now, waitEnterMs_);
        if (waitMs_ <= UINT32_MAX - delta) {
            waitMs_ += delta;
        } else {
            waitMs_ = UINT32_MAX;
        }
        inWait_ = false;
    }
}

uint32_t TimingTracer::SafeSubToU32(uint64_t end, uint64_t start) const
{
    if (end < start) {
        return 0;
    }
    uint64_t diff = end - start;
    return (diff > UINT32_MAX) ? UINT32_MAX : static_cast<uint32_t>(diff);
}

void TimingTracer::Mark(StageId id)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    points_.push_back(Point { id, now });
}

void TimingTracer::EnterWait(StageId id)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    inWait_ = true;
    waitEnterMs_ = now;
    points_.push_back(Point { id, now });
}

void TimingTracer::ExitWait(StageId id)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    points_.push_back(Point { id, now });
}

void TimingTracer::Finish()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value()) {
        return;
    }
    uint64_t now = Now();
    CloseWaitIfNeeded(now);
    endMs_ = now;
}

uint32_t TimingTracer::TotalMs() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value() || !endMs_.has_value() || *endMs_ < *startMs_) {
        return 0;
    }
    return SafeSubToU32(*endMs_, *startMs_);
}

uint32_t TimingTracer::LocalMs() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    uint32_t total = TotalMs();
    return (total >= waitMs_) ? (total - waitMs_) : 0;
}

uint32_t TimingTracer::AuthTipMs() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value()) {
        return 0;
    }
    for (const auto &point : points_) {
        if (point.id == StageId::S_ON_TIP_AUTH_SUCC) {
            return SafeSubToU32(point.absMs, *startMs_);
        }
    }
    return 0;
}

std::string TimingTracer::ExportTrace() const
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!startMs_.has_value() || points_.empty()) {
        return "";
    }
    std::ostringstream oss;
    for (size_t i = 0; i < points_.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        uint64_t delta = (points_[i].absMs >= *startMs_) ? (points_[i].absMs - *startMs_) : 0;
        oss << static_cast<uint32_t>(points_[i].id) << ":" << delta;
    }
    return oss.str();
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS