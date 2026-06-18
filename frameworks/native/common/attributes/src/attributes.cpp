/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "attributes.h"

#include <map>
#include <memory>
#include <endian.h>

#include "iam_logger.h"
#include "securec.h"

#define LOG_FILE_ID LOG_FILE_ATTRIBUTES
namespace OHOS {
namespace UserIam {
namespace UserAuth {
#define LOG_TAG "USER_AUTH_SA"
class Attributes::Impl {
public:
    Impl() = default;

    explicit Impl(const std::vector<uint8_t> &raw);

    Impl(const Impl &other) = delete;
    Impl &operator=(const Impl &other) = delete;

    Impl(Impl &&other) noexcept;
    Impl &operator=(Impl &&other) noexcept;

    virtual ~Impl() = default;

    bool SetBoolValue(AttributeKey key, bool value);
    bool SetUint64Value(AttributeKey key, uint64_t value);
    bool SetUint32Value(AttributeKey key, uint32_t value);
    bool SetUint16Value(AttributeKey key, uint16_t value);
    bool SetUint8Value(AttributeKey key, uint8_t value);
    bool SetInt32Value(AttributeKey key, int32_t value);
    bool SetInt64Value(AttributeKey key, int64_t value);
    bool SetStringValue(AttributeKey key, const std::string &value);
    bool SetAttributesValue(AttributeKey key, const Impl &array);
    bool SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value);
    bool SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value);
    bool SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value);
    bool SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value);
    bool SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value);

    bool GetBoolValue(AttributeKey key, bool &value) const;
    bool GetUint64Value(AttributeKey key, uint64_t &value) const;
    bool GetUint32Value(AttributeKey key, uint32_t &value) const;
    bool GetUint16Value(AttributeKey key, uint16_t &value) const;
    bool GetUint8Value(AttributeKey key, uint8_t &value) const;
    bool GetInt32Value(AttributeKey key, int32_t &value) const;
    bool GetInt64Value(AttributeKey key, int64_t &value) const;
    bool GetStringValue(AttributeKey key, std::string &value) const;
    bool GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const;
    bool GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const;
    bool GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const;
    bool GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const;
    bool GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const;
    bool GetAttributesValue(AttributeKey key, Impl &array) const;
    std::vector<uint8_t> Serialize() const;
    std::vector<AttributeKey> GetKeys() const;
    bool HasAttribute(AttributeKey key) const;

    static bool EncodeUint32Value(uint32_t src, std::vector<uint8_t> &dst);
    static bool DecodeUint32Value(const std::vector<uint8_t> &src, uint32_t &dst);

private:
    static constexpr uint32_t MAX_ATTR_LENGTH = 81920;
    static constexpr uint32_t MAX_ATTR_COUNT = 512;
    static bool EncodeBoolValue(bool src, std::vector<uint8_t> &dst);
    static bool EncodeUint64Value(uint64_t src, std::vector<uint8_t> &dst);
    static bool EncodeUint16Value(uint16_t src, std::vector<uint8_t> &dst);
    static bool EncodeUint8Value(uint8_t src, std::vector<uint8_t> &dst);
    static bool EncodeInt32Value(int32_t src, std::vector<uint8_t> &dst);
    static bool EncodeInt64Value(int64_t src, std::vector<uint8_t> &dst);
    static bool EncodeStringValue(const std::string &src, std::vector<uint8_t> &dst);
    static bool EncodeUint64ArrayValue(const std::vector<uint64_t> &src, std::vector<uint8_t> &dst);
    static bool EncodeInt32ArrayValue(const std::vector<int32_t> &src, std::vector<uint8_t> &dst);
    static bool EncodeUint32ArrayValue(const std::vector<uint32_t> &src, std::vector<uint8_t> &dst);
    static bool EncodeUint16ArrayValue(const std::vector<uint16_t> &src, std::vector<uint8_t> &dst);
    static bool EncodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst);

    static bool DecodeBoolValue(const std::vector<uint8_t> &src, bool &dst);
    static bool DecodeUint64Value(const std::vector<uint8_t> &src, uint64_t &dst);
    static bool DecodeUint16Value(const std::vector<uint8_t> &src, uint16_t &dst);
    static bool DecodeUint8Value(const std::vector<uint8_t> &src, uint8_t &dst);
    static bool DecodeInt32Value(const std::vector<uint8_t> &src, int32_t &dst);
    static bool DecodeInt64Value(const std::vector<uint8_t> &src, int64_t &dst);
    static bool DecodeStringValue(const std::vector<uint8_t> &src, std::string &dst);
    static bool DecodeUint64ArrayValue(const std::vector<uint8_t> &src, std::vector<uint64_t> &dst);
    static bool DecodeUint32ArrayValue(const std::vector<uint8_t> &src, std::vector<uint32_t> &dst);
    static bool DecodeUint16ArrayValue(const std::vector<uint8_t> &src, std::vector<uint16_t> &dst);
    static bool DecodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst);
    static bool DecodeInt32ArrayValue(const std::vector<uint8_t> &src, std::vector<int32_t> &dst);
    static bool CheckAttributeLength(const uint8_t *curr, const uint8_t *end, uint32_t length);
    static bool ParseAttributes(const uint8_t *&curr, const uint8_t *&end,
        std::map<Attributes::AttributeKey, std::vector<uint8_t>> &out);
    std::map<AttributeKey, std::vector<uint8_t>> map_;
};

Attributes::Impl::Impl(const std::vector<uint8_t> &raw)
{
    if (raw.empty()) {
        IAM_LOGE("raw is empty.");
        return;
    }
    std::map<Attributes::AttributeKey, std::vector<uint8_t>> out;

    const uint8_t *curr = &raw.front();
    const uint8_t *end = &raw.back() + sizeof(uint8_t);
    constexpr size_t headerSize = sizeof(uint32_t) + sizeof(uint32_t);
    while (curr < end) {
        size_t remaining = static_cast<size_t>(end - curr);
        if (remaining < headerSize) {
            IAM_LOGE("insufficient data");
            return;
        }

        if (!ParseAttributes(curr, end, out)) {
            IAM_LOGE("ParseAttributes failed.");
            return;
        }
    }

    map_.swap(out);
}

bool Attributes::Impl::ParseAttributes(const uint8_t *&curr, const uint8_t *&end,
    std::map<Attributes::AttributeKey, std::vector<uint8_t>> &out)
{
    uint32_t type;
    if (memcpy_s(&type, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
        IAM_LOGE("type copy error");
        return false;
    }

    type = le32toh(type);
    curr += sizeof(uint32_t);
    uint32_t length;
    if (memcpy_s(&length, sizeof(uint32_t), curr, sizeof(uint32_t)) != EOK) {
        IAM_LOGE("length copy error");
        return false;
    }
    length = le32toh(length);
    curr += sizeof(uint32_t);
    if (!CheckAttributeLength(curr, end, length)) {
        IAM_LOGE("check attribute length error");
        return false;
    }

    std::vector<uint8_t> value(length / sizeof(uint8_t));
    if (length != 0 && memcpy_s(value.data(), value.size() * sizeof(uint8_t), curr, length) != EOK) {
        IAM_LOGE("value copy error, length = %{public}u", length);
        return false;
    }

    auto ret = out.insert_or_assign(static_cast<Attributes::AttributeKey>(type), value);
    if (!ret.second) {
        IAM_LOGE("insert_or_assign pair error, type is %{public}u", type);
        return false;
    }

    if (out.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("insert_or_assign pair error, size reach max");
        return false;
    }

    IAM_LOGD("insert_or_assign pair success, type is %{public}u", type);
    curr += length;
    return true;
}

Attributes::Impl::Impl(Attributes::Impl &&other) noexcept : map_(std::move(other.map_))
{
}

Attributes::Impl &Attributes::Impl::operator=(Attributes::Impl &&other) noexcept
{
    map_ = std::move(other.map_);
    return *this;
}

bool Attributes::Impl::CheckAttributeLength(const uint8_t *curr, const uint8_t *end, uint32_t length)
{
    if (length % sizeof(uint8_t) != 0 || length > MAX_ATTR_LENGTH) {
        IAM_LOGE("length format error, length = %{public}u", length);
        return false;
    }
    if (static_cast<std::ptrdiff_t>(length) > end - curr) {
        IAM_LOGE("length too big, length = %{public}u", length);
        return false;
    }
    return true;
}

bool Attributes::Impl::SetBoolValue(AttributeKey key, bool value)
{
    std::vector<uint8_t> dest;
    if (!EncodeBoolValue(value, dest)) {
        IAM_LOGE("EncodeBoolValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint64Value(AttributeKey key, uint64_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint64Value(value, dest)) {
        IAM_LOGE("EncodeUint64Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint32Value(AttributeKey key, uint32_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint32Value(value, dest)) {
        IAM_LOGE("EncodeUint32Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint16Value(AttributeKey key, uint16_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint16Value(value, dest)) {
        IAM_LOGE("EncodeUint16Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint8Value(AttributeKey key, uint8_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint8Value(value, dest)) {
        IAM_LOGE("EncodeUint8Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_[key] = dest;
    return true;
}

bool Attributes::Impl::SetInt32Value(AttributeKey key, int32_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeInt32Value(value, dest)) {
        IAM_LOGE("EncodeInt32Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetInt64Value(AttributeKey key, int64_t value)
{
    std::vector<uint8_t> dest;
    if (!EncodeInt64Value(value, dest)) {
        IAM_LOGE("EncodeInt64Value error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    auto ret = map_.try_emplace(key, dest);
    return ret.second;
}

bool Attributes::Impl::SetStringValue(AttributeKey key, const std::string &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeStringValue(value, dest)) {
        IAM_LOGE("EncodeStringValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint64ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint64ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint32ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint32ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeInt32ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint32ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint16ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint16ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value)
{
    std::vector<uint8_t> dest;
    if (!EncodeUint8ArrayValue(value, dest)) {
        IAM_LOGE("EncodeUint8ArrayValue error");
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::SetAttributesValue(Attributes::AttributeKey key, const Attributes::Impl &value)
{
    std::vector<uint8_t> dest = value.Serialize();
    if (dest.empty()) {
        return false;
    }

    if (map_.size() > MAX_ATTR_COUNT) {
        IAM_LOGE("attrs size reach max");
        return false;
    }

    map_.insert_or_assign(key, dest);
    return true;
}

bool Attributes::Impl::GetBoolValue(AttributeKey key, bool &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeBoolValue(iter->second, value)) {
        IAM_LOGE("DecodeBoolValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint64Value(AttributeKey key, uint64_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint64Value(iter->second, value)) {
        IAM_LOGE("DecodeUint64Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint32Value(AttributeKey key, uint32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint32Value(iter->second, value)) {
        IAM_LOGE("DecodeUint32Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint16Value(AttributeKey key, uint16_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint16Value(iter->second, value)) {
        IAM_LOGE("DecodeUint16Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint8Value(AttributeKey key, uint8_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint8Value(iter->second, value)) {
        IAM_LOGE("DecodeUint8Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetInt32Value(AttributeKey key, int32_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeInt32Value(iter->second, value)) {
        IAM_LOGE("DecodeInt32Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetInt64Value(AttributeKey key, int64_t &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeInt64Value(iter->second, value)) {
        IAM_LOGE("DecodeInt64Value error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetStringValue(AttributeKey key, std::string &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeStringValue(iter->second, value)) {
        IAM_LOGE("DecodeStringValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint64ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint64ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint32ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint32ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeInt32ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint32ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint16ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint16ArrayValue error");
        return false;
    }

    return true;
}

bool Attributes::Impl::GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }

    if (!DecodeUint8ArrayValue(iter->second, value)) {
        IAM_LOGE("DecodeUint8ArrayValue error");
        return false;
    }
    return true;
}

bool Attributes::Impl::GetAttributesValue(Attributes::AttributeKey key, Attributes::Impl &value) const
{
    auto iter = map_.find(key);
    if (iter == map_.end()) {
        return false;
    }
    Attributes::Impl out(iter->second);
    value = std::move(out);
    return true;
}

std::vector<uint8_t> Attributes::Impl::Serialize() const
{
    uint32_t size = 0;
    for (const auto &[key, value] : map_) {
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += sizeof(uint32_t) / sizeof(uint8_t);
        size += value.size();
    }
    std::vector<uint8_t> buffer;
    buffer.reserve(size);

    for (const auto &[key, value] : map_) {
        std::vector<uint8_t> type;
        std::vector<uint8_t> length;
        if (!EncodeUint32Value(key, type)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value key error");
            break;
        }
        if (!EncodeUint32Value(value.size() * sizeof(uint8_t), length)) {
            buffer.clear();
            IAM_LOGE("EncodeUint32Value value error");
            break;
        }
        buffer.insert(buffer.end(), type.begin(), type.end());
        buffer.insert(buffer.end(), length.begin(), length.end());
        buffer.insert(buffer.end(), value.begin(), value.end());
    }
    return buffer;
}

std::vector<Attributes::AttributeKey> Attributes::Impl::GetKeys() const
{
    std::vector<Attributes::AttributeKey> keys;
    keys.reserve(map_.size());
    for (auto const &item : map_) {
        keys.push_back(item.first);
    }
    return keys;
}

bool Attributes::Impl::HasAttribute(AttributeKey key) const
{
    return (map_.find(key) != map_.end());
}

bool Attributes::Impl::EncodeBoolValue(bool src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(1); // only 1
    out[0] = src ? 1 : 0;

    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint64Value(uint64_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint64_t) / sizeof(uint8_t));
    uint64_t srcLe64 = htole64(src);
    if (memcpy_s(out.data(), out.size(), &srcLe64, sizeof(srcLe64)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint32Value(uint32_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint32_t) / sizeof(uint8_t));
    uint32_t srcLe32 = htole32(src);
    if (memcpy_s(out.data(), out.size(), &srcLe32, sizeof(srcLe32)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint16Value(uint16_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(uint16_t) / sizeof(uint8_t));
    uint16_t srcLe16 = htole16(src);
    if (memcpy_s(out.data(), out.size(), &srcLe16, sizeof(srcLe16)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint8Value(uint8_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(1);
    out[0] = src;
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeInt32Value(int32_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(int32_t) / sizeof(uint8_t));

    uint32_t srcLe32 = htole32(static_cast<uint32_t>(src));
    if (memcpy_s(out.data(), out.size(), &srcLe32, sizeof(srcLe32)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeInt64Value(int64_t src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(sizeof(int64_t) / sizeof(uint8_t));

    uint64_t srcLe64 = htole64(static_cast<uint64_t>(src));
    if (memcpy_s(out.data(), out.size(), &srcLe64, sizeof(srcLe64)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeStringValue(const std::string &src, std::vector<uint8_t> &dst)
{
    if (src.size() > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(src.begin(), src.end());
    out.push_back(0);
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint64ArrayValue(const std::vector<uint64_t> &src, std::vector<uint8_t> &dst)
{
    auto outSize = src.size() * (sizeof(uint64_t) / sizeof(uint8_t));
    if (outSize > MAX_ATTR_LENGTH) {
        return false;
    }
    std::vector<uint8_t> out(outSize);
    std::vector<uint64_t> srcLe64(src.size());
    for (uint32_t i = 0; i < src.size();i++) {
        srcLe64[i] = htole64(src[i]);
    }
    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), srcLe64.data(), srcLe64.size() * sizeof(uint64_t)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint32ArrayValue(const std::vector<uint32_t> &src, std::vector<uint8_t> &dst)
{
    auto outSize = src.size() * (sizeof(uint32_t) / sizeof(uint8_t));
    if (outSize > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(outSize);
    std::vector<uint32_t> srcLe32(src.size());
    for (uint32_t i = 0; i < src.size();i++) {
        srcLe32[i] = htole32(src[i]);
    }

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), srcLe32.data(), srcLe32.size() * sizeof(uint32_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint16ArrayValue(const std::vector<uint16_t> &src, std::vector<uint8_t> &dst)
{
    auto outSize = src.size() * (sizeof(uint16_t) / sizeof(uint8_t));
    if (outSize > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(outSize);
    std::vector<uint16_t> srcLe16(src.size());
    for (uint32_t i = 0; i < src.size();i++) {
        srcLe16[i] = htole16(src[i]);
    }

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), srcLe16.data(), srcLe16.size() * sizeof(uint16_t)) != EOK) {
        return false;
    }
    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeInt32ArrayValue(const std::vector<int32_t> &src, std::vector<uint8_t> &dst)
{
    auto outSize = src.size() * (sizeof(int32_t) / sizeof(uint8_t));
    if (outSize > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(outSize);
    std::vector<uint32_t> srcLe32(src.size());
    for (uint32_t i = 0; i < src.size();i++) {
        srcLe32[i] = htole32(static_cast<uint32_t>(src[i]));
    }

    if (!src.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint8_t), srcLe32.data(), srcLe32.size() * sizeof(int32_t)) != EOK) {
        return false;
    }

    dst.swap(out);
    return true;
}

bool Attributes::Impl::EncodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst)
{
    if (src.size() > MAX_ATTR_LENGTH) {
        return false;
    }

    std::vector<uint8_t> out(src);
    dst.swap(out);
    return true;
}

bool Attributes::Impl::DecodeBoolValue(const std::vector<uint8_t> &src, bool &dst)
{
    if (src.size() != 1) {
        return false;
    }
    dst = (src[0] == 1);
    return true;
}

bool Attributes::Impl::DecodeUint64Value(const std::vector<uint8_t> &src, uint64_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint64_t)) {
        return false;
    }

    uint64_t dstLe64;
    if (memcpy_s(&dstLe64, sizeof(dstLe64), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    dst = le64toh(dstLe64);
    return true;
}

bool Attributes::Impl::DecodeUint32Value(const std::vector<uint8_t> &src, uint32_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint32_t)) {
        return false;
    }

    uint32_t dstLe32;
    if (memcpy_s(&dstLe32, sizeof(dstLe32), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    dst = le32toh(dstLe32);

    return true;
}

bool Attributes::Impl::DecodeUint16Value(const std::vector<uint8_t> &src, uint16_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(uint16_t)) {
        return false;
    }

    uint16_t dstLe16;
    if (memcpy_s(&dstLe16, sizeof(dstLe16), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    dst = le16toh(dstLe16);
    return true;
}

bool Attributes::Impl::DecodeUint8Value(const std::vector<uint8_t> &src, uint8_t &dst)
{
    if (src.size() != 1) {
        return false;
    }
    dst = src[0];
    return true;
}

bool Attributes::Impl::DecodeInt32Value(const std::vector<uint8_t> &src, int32_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(int32_t)) {
        return false;
    }

    uint32_t dstLe32;
    if (memcpy_s(&dstLe32, sizeof(dstLe32), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    dst = static_cast<int32_t>(le32toh(dstLe32));

    return true;
}

bool Attributes::Impl::DecodeInt64Value(const std::vector<uint8_t> &src, int64_t &dst)
{
    if (src.size() * sizeof(uint8_t) != sizeof(int64_t)) {
        return false;
    }

    uint64_t dstLe64;
    if (memcpy_s(&dstLe64, sizeof(dstLe64), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }
    dst = static_cast<int64_t>(le64toh(dstLe64));
    return true;
}

bool Attributes::Impl::DecodeStringValue(const std::vector<uint8_t> &src, std::string &dst)
{
    if (src.empty()) {
        return false;
    }

    if (src.back() != 0) {
        return false;
    }

    dst.assign(src.begin(), src.end() -1);
    return true;
}

bool Attributes::Impl::DecodeUint64ArrayValue(const std::vector<uint8_t> &src, std::vector<uint64_t> &dst)
{
    if (src.size() % (sizeof(uint64_t) / sizeof(uint8_t)) != 0) {
        return false;
    }

    std::vector<uint64_t> out(src.size() / (sizeof(uint64_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint64_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    for (uint32_t i = 0; i < out.size(); i++) {
        out[i] = le64toh(out[i]);
    }

    dst.swap(out);
    return true;
}

bool Attributes::Impl::DecodeUint32ArrayValue(const std::vector<uint8_t> &src, std::vector<uint32_t> &dst)
{
    if (src.size() % (sizeof(uint32_t) / sizeof(uint8_t)) != 0) {
        return false;
    }

    std::vector<uint32_t> out(src.size() / (sizeof(uint32_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint32_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    for (uint32_t i = 0; i < out.size(); i++) {
        out[i] = le32toh(out[i]);
    }

    dst.swap(out);
    return true;
}

bool Attributes::Impl::DecodeUint16ArrayValue(const std::vector<uint8_t> &src, std::vector<uint16_t> &dst)
{
    if (src.size() % (sizeof(uint32_t) / sizeof(uint16_t)) != 0) {
        return false;
    }

    std::vector<uint16_t> out(src.size() / (sizeof(uint16_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(uint16_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    for (uint32_t i = 0; i < out.size(); i++) {
        out[i] = le16toh(out[i]);
    }

    dst.swap(out);
    return true;
}

bool Attributes::Impl::DecodeUint8ArrayValue(const std::vector<uint8_t> &src, std::vector<uint8_t> &dst)
{
    std::vector<uint8_t> out(src);
    dst.swap(out);
    return true;
}

bool Attributes::Impl::DecodeInt32ArrayValue(const std::vector<uint8_t> &src, std::vector<int32_t> &dst)
{
    if (src.size() % (sizeof(int32_t) / sizeof(uint8_t)) != 0) {
        return false;
    }

    std::vector<int32_t> out(src.size() / (sizeof(int32_t) / sizeof(uint8_t)));

    if (!out.empty() &&
        memcpy_s(out.data(), out.size() * sizeof(int32_t), src.data(), src.size() * sizeof(uint8_t)) != EOK) {
        return false;
    }

    for (uint32_t i = 0; i < out.size(); i++) {
        out[i] = static_cast<int32_t>(le32toh(static_cast<uint32_t>(out[i])));
    }

    dst.swap(out);
    return true;
}

Attributes::Attributes() : impl_(new (std::nothrow) Attributes::Impl())
{
}

Attributes::Attributes(const std::vector<uint8_t> &raw) : impl_(new (std::nothrow) Attributes::Impl(raw))
{
}

Attributes::Attributes(Attributes &&other) noexcept : impl_(std::move(other.impl_))
{
}

Attributes &Attributes::operator=(Attributes &&other) noexcept
{
    impl_ = std::move(other.impl_);
    return *this;
}

Attributes::~Attributes()
{
    impl_ = nullptr;
};

bool Attributes::SetBoolValue(AttributeKey key, bool value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetBoolValue(key, value);
}

bool Attributes::SetUint64Value(AttributeKey key, uint64_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint64Value(key, value);
}

bool Attributes::SetUint32Value(AttributeKey key, uint32_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint32Value(key, value);
}

bool Attributes::SetUint16Value(AttributeKey key, uint16_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint16Value(key, value);
}

bool Attributes::SetUint8Value(AttributeKey key, uint8_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint8Value(key, value);
}

bool Attributes::SetInt32Value(AttributeKey key, int32_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetInt32Value(key, value);
}

bool Attributes::SetInt64Value(AttributeKey key, int64_t value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetInt64Value(key, value);
}

bool Attributes::SetStringValue(AttributeKey key, const std::string &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetStringValue(key, value);
}

bool Attributes::SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint64ArrayValue(key, value);
}

bool Attributes::SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint32ArrayValue(key, value);
}

bool Attributes::SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint16ArrayValue(key, value);
}

bool Attributes::SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetUint8ArrayValue(key, value);
}

bool Attributes::SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetInt32ArrayValue(key, value);
}

bool Attributes::SetAttributesValue(AttributeKey key, const Attributes &value)
{
    if (!impl_) {
        return false;
    }
    return impl_->SetAttributesValue(key, *value.impl_);
}

bool Attributes::SetAttributesArrayValue(AttributeKey key, const std::vector<Attributes> &array)
{
    if (!impl_) {
        return false;
    }

    std::vector<std::vector<uint8_t>> serializedArray;
    for (auto &item : array) {
        if (!item.impl_) {
            return false;
        }
        serializedArray.push_back(item.Serialize());
    }

    uint32_t dataLen = 0;
    for (auto &array : serializedArray) {
        dataLen += (sizeof(uint32_t) + array.size());
    }

    std::vector<uint8_t> data;
    data.reserve(dataLen);
    for (auto &array : serializedArray) {
        std::vector<uint8_t> arrayLen;
        bool encodeRet = Attributes::Impl::EncodeUint32Value(array.size(), arrayLen);
        if (!encodeRet) {
            return false;
        }
        std::copy(arrayLen.begin(), arrayLen.end(), std::back_inserter(data));
        std::copy(array.begin(), array.end(), std::back_inserter(data));
    }

    return impl_->SetUint8ArrayValue(key, data);
}

bool Attributes::GetAttributesArrayValue(AttributeKey key, std::vector<Attributes> &array) const
{
    if (!impl_) {
        return false;
    }

    std::vector<uint8_t> data;
    bool getDataRet = impl_->GetUint8ArrayValue(key, data);
    if (!getDataRet) {
        return false;
    }

    array.clear();
    uint32_t i = 0;
    while (i < data.size()) {
        if (data.size() - i < sizeof(uint32_t)) {
            return false;
        }

        std::vector<uint8_t> arrayLenData(data.begin() + i, data.begin() + i + sizeof(uint32_t));
        uint32_t arrayLen;
        bool decodeRet = Attributes::Impl::DecodeUint32Value(arrayLenData, arrayLen);
        if (!decodeRet) {
            return false;
        }
        i += sizeof(uint32_t);

        if (data.size() - i < arrayLen) {
            return false;
        }

        array.push_back(Attributes(std::vector<uint8_t>(data.begin() + i, data.begin() + i + arrayLen)));
        i += arrayLen;
    }

    return true;
}

bool Attributes::GetBoolValue(AttributeKey key, bool &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetBoolValue(key, value);
}

bool Attributes::GetUint64Value(AttributeKey key, uint64_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint64Value(key, value);
}

bool Attributes::GetUint32Value(AttributeKey key, uint32_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint32Value(key, value);
}

bool Attributes::GetUint16Value(AttributeKey key, uint16_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint16Value(key, value);
}

bool Attributes::GetUint8Value(AttributeKey key, uint8_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint8Value(key, value);
}

bool Attributes::GetInt32Value(AttributeKey key, int32_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetInt32Value(key, value);
}

bool Attributes::GetInt64Value(AttributeKey key, int64_t &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetInt64Value(key, value);
}

bool Attributes::GetStringValue(AttributeKey key, std::string &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetStringValue(key, value);
}

bool Attributes::GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint64ArrayValue(key, value);
}

bool Attributes::GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint32ArrayValue(key, value);
}

bool Attributes::GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint16ArrayValue(key, value);
}

bool Attributes::GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetUint8ArrayValue(key, value);
}

bool Attributes::GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetInt32ArrayValue(key, value);
}

bool Attributes::GetAttributesValue(AttributeKey key, Attributes &value) const
{
    if (!impl_) {
        return false;
    }
    return impl_->GetAttributesValue(key, *value.impl_);
}

std::vector<uint8_t> Attributes::Serialize() const
{
    if (!impl_) {
        return {};
    }
    return impl_->Serialize();
}

std::vector<Attributes::AttributeKey> Attributes::GetKeys() const
{
    if (!impl_) {
        return {};
    }
    return impl_->GetKeys();
}

bool Attributes::HasAttribute(AttributeKey key) const
{
    if (!impl_) {
        return false;
    }
    return impl_->HasAttribute(key);
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS