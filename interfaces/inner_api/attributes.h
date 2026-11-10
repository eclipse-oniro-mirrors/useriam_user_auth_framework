/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

/**
 * @file attributes.h
 *
 * @brief Attributes enum define.
 * @since 3.1
 * @version 3.2
 */

#ifndef IAM_ATTRIBUTES_H
#define IAM_ATTRIBUTES_H

#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace UserIam {
namespace UserAuth {
class Attributes final {
public:
    /**
     * @brief The key to set attribute.
     */
    enum AttributeKey : uint32_t {
        /** Root tag, the value type is std::vector<uint8_t>. */
        ATTR_ROOT = 100000,
        /** Result code, the value type is int32_t. */
        ATTR_RESULT_CODE = 100001,
        /** Signature, the value type is std::vector<uint8_t>. */
        ATTR_SIGNATURE = 100004,
        /** Identify mode, the value type is uint32_t. */
        ATTR_IDENTIFY_MODE = 100005,
        /** Template ID, the value type is uint64_t. */
        ATTR_TEMPLATE_ID = 100006,
        /** Template ID list, the value type is std::vector<uint64_t>. */
        ATTR_TEMPLATE_ID_LIST = 100007,
        /** Attribute error count, the value type is int32_t. */
        ATTR_ERROR_COUNT = 100008,
        /** Remain time, the value type is int32_t. */
        ATTR_REMAIN_TIMES = 100009,
        ATTR_REMAIN_ATTEMPTS = ATTR_REMAIN_TIMES,
        /** Freezing time, the value type is int32_t. */
        ATTR_FREEZING_TIME = 100010,
        ATTR_LOCKOUT_DURATION = ATTR_FREEZING_TIME,
        /** Session ID, the value type is uint64_t. */
        ATTR_SESSION_ID = 100014,
        /** Caller package name, the value type is string. */
        ATTR_CALLER_NAME = 100015,
        /** Schedule version, the value type is uint32_t. */
        ATTR_SCHEDULE_VERSION = 100016,
        /** Schedule ID, the value type is uint64_t. */
        ATTR_SCHEDULE_ID = 100017,
        /** Locked templates, the value type is std::vector<uint64_t>. */
        ATTR_LOCKED_TEMPLATES = 100018,
        /** Unlocked templates, the value type is std::vector<uint64_t>. */
        ATTR_UNLOCKED_TEMPLATES = 100019,
        /** Data, the value type is std::vector<uint8_t>. */
        ATTR_DATA = 100020,
        /** Pin subtype, the value type is int32_t. */
        ATTR_PIN_SUB_TYPE = 100021,
        /** Schedule mode, the value type is int32_t. */
        ATTR_SCHEDULE_MODE = 100022,
        /** Property mode, the value type is uint32_t. */
        ATTR_PROPERTY_MODE = 100023,
        /** Authenticate type, the value type is int32_t. */
        ATTR_AUTH_TYPE = 100024,
        /** Credential ID, the value type is uint64_t. */
        ATTR_CREDENTIAL_ID = 100025,
        /** Caller UID, the value type is uint64_t. */
        ATTR_CALLER_UID = 100027,
        /** Tag of result, the value type is std::vector<uint8_t>. */
        ATTR_RESULT = 100028,
        /** Capability level, the value type is uint64_t. */
        ATTR_CAPABILITY_LEVEL = 100029,
        /** Algorithm information, the value type is uint64_t. */
        ATTR_ALGORITHM_INFO = 100030,
        /** Timer stamp, the value type is uint64_t. */
        ATTR_TIME_STAMP = 100031,
        /** Root secret, the value type is std::vector<uint8_t>. */
        ATTR_ROOT_SECRET = 100032,
        /** Auth token, the value type is std::vector<uint8_t>. */
        ATTR_AUTH_TOKEN = 100033,
        /** Security user ID return when add pin credential, the value type is uint64_t. */
        ATTR_SEC_USER_ID = 100034,
        /** Enroll progress, the value type is string. */
        ATTR_ENROLL_PROGRESS = 100035,
        /** Sensor info, the value type is string. */
        ATTR_SENSOR_INFO = 100036,
        /** Key list, the value type is std::vector<uint32_t>. */
        ATTR_KEY_LIST = 100037,
        /** End after first fail, the value type is boolean. */
        ATTR_END_AFTER_FIRST_FAIL = 100038,
        /** Tip info, the value type is int32_t. */
        ATTR_TIP_INFO = 100039,
        /** Old root secret, the value type is std::vector<uint8_t>. */
        ATTR_OLD_ROOT_SECRET = 100040,
        /** Old credential ID, the value type is uint64_t. */
        ATTR_OLD_CREDENTIAL_ID = 100041,
        /** Source role, the value type is int32_t. */
        ATTR_SRC_ROLE = 100042,
        /** User ID, the value type is int32_t. */
        ATTR_USER_ID = 100043,
        /** Extra information, the value type is std::vector<uint8_t>. */
        ATTR_EXTRA_INFO = 100044,
        /** Executor ID, the value type is uint64_t. */
        ATTR_EXECUTOR_INDEX = 100045,
        /** Executor sensor hint, the value type is uint32_t. */
        ATTR_EXECUTOR_SENSOR_HINT = 100046,
        /** Executor matcher, the value type is uint32_t. */
        ATTR_EXECUTOR_MATCHER = 100047,
        /** Access token ID, the value type is uint32_t. */
        ATTR_ACCESS_TOKEN_ID = 100048,
        /** Template change reason, the value type is string. */
        ATTR_TEMPLATE_CHANGE_REASON = 100049,
        /** Credential digest, the value type is uint64_t. */
        ATTR_CREDENTIAL_DIGEST = 100050,
        /** Credential count, the value type is uint16_t. */
        ATTR_CREDENTIAL_COUNT = 100051,
        /** Message sequence number, the value type is uint32_t. */
        ATTR_MSG_SEQ_NUM = 100052,
        /** Reply message, the value type is bool. */
        ATTR_MSG_ACK = 100053,
        /** Message source UDID, the value type is string. */
        ATTR_MSG_SRC_UDID = 100054,
        /** Source of message, the value type is string. */
        ATTR_MSG_SRC_END_POINT = 100055,
        /** Destination of message, the value type is string. */
        ATTR_MSG_DEST_END_POINT = 100056,
        /** Connection name, the value type is string. */
        ATTR_CONNECTION_NAME = 100057,
        /** Message version, the value type is uint32_t. */
        ATTR_MSG_VERSION = 100058,
        /** Message type, the value type is int32_t. */
        ATTR_MSG_TYPE = 100059,
        /** Message reply sequence number, the value type is uint32_t. */
        ATTR_MSG_REPLY_SEQ_NUM = 100060,
        /** Context ID, the value type is uint64_t. */
        ATTR_CONTEXT_ID = 100061,
        /** Collector info, the value type is std::vector<uint8_t>. */
        ATTR_COLLECTOR_INFO = 100062,
        /** Executor role, the value type is int32_t. */
        ATTR_EXECUTOR_ROLE = 100063,
        /** Schedule data, the value type is std::vector<uint8_t>. */
        ATTR_SCHEDULE_DATA = 100064,
        /** Signed authentication result, the value type is std::vector<uint8_t>. */
        ATTR_SIGNED_AUTH_RESULT = 100065,
        /** Destination role, the value type is int32_t. */
        ATTR_DEST_ROLE = 100066,
        /** Local UDID, the value type is string. */
        ATTR_LOCAL_UDID = 100067,
        /** Peer UDID, the value type is string. */
        ATTR_PEER_UDID = 100068,
        /** Public key, the value type is std::vector<uint8_t>. */
        ATTR_PUBLIC_KEY = 100069,
        /** Executor info list, the value type is std::vector<uint8_t>. */
        ATTR_EXECUTOR_REGISTER_INFO_LIST = 100070,
        /** Executor secure level, the value type is int32_t. */
        ATTR_ESL = 100071,
        /** Challenge, the value type is std::vector<uint8_t>. */
        ATTR_CHALLENGE = 100072,
        /** Remote executor info, the value type is std::vector<uint8_t>. */
        ATTR_REMOTE_EXECUTOR_INFO = 100073,
        /** Authentication types, the value type is std::vector<int32_t>. */
        ATTR_AUTH_TYPES = 100074,
        /** Authentication trust level, the value type is int32_t. */
        ATTR_AUTH_TRUST_LEVEL = 100075,
        /** Device UDID, the value type is string. */
        ATTR_DEVICE_UDID = 100080,
        /** Collector network id. */
        ATTR_COLLECTOR_NETWORK_ID = 100081,
        /** Collector token id. */
        ATTR_COLLECTOR_TOKEN_ID = 100082,
        /** Pin expired info, the value type is int64_t and it's max value is 2^50. */
        ATTR_PIN_EXPIRED_INFO = 100083,
        /** next fail lockout duration, the value type is int32_t. */
        ATTR_NEXT_FAIL_LOCKOUT_DURATION = 100084,
        /** caller type, the value type is int32_t. */
        ATTR_CALLER_TYPE = 100085,
        /* auth intention */
        ATTR_AUTH_INTENTION = 100086,
        /** Supported message version, the value type is std::vector<uint32_t>. */
        ATTR_SUPPORTED_MSG_VERSION = 100087,
        /* re-enroll flag, the value type is bool */
        ATTR_RE_ENROLL_FLAG = 100088,
        /* Token version, the value type is uint32_t. */
        ATTR_TOKEN_VERSION = 100089,
        /* Token type of token, the value type is int32_t. */
        ATTR_TOKEN_TYPE = 100090,
        /* Token time interval between sign and verify, the value type is int64_t. */
        ATTR_TOKEN_TIME_INTERVAL = 100091,
        /* credential length, the value type is uint32_t. */
        ATTR_CREDENTIAL_LENGTH = 100092,
        /*
         * Is token in attribute generated by remote device, if not setted indicate token generated by local device.
         * The value type is bool.
         */
        ATTR_TOKEN_FROM_REMOTE_DEVICE = 100093,
        /** Additional info from caller, the value type is string. */
        ATTR_ADDITIONAL_INFO = 100094,
        /** Auth scene, the value type is int32_t. */
        ATTR_AUTH_SCENE = 100095,
        /** Widget title, the value type is string. */
        ATTR_WIDGET_TITLE = 100096,
        /** Camera status, the value type is uint32_t. */
        ATTR_CAMERA_STATUS  = 100097,
        /* Pin abandon flag, the value type is bool */
        ATTR_ABANDON_FLAG = 100098,
    };

    /**
     * @brief Default constructor.
     */
    Attributes();

    /**
     * @brief Overload constructor.
     *
     * This constructor prohibits implicit type conversion of input parameters.
     *
     * @param raw The value to be passed in when defining Attribute.
     */
    explicit Attributes(const std::vector<uint8_t> &raw);

    /**
     * @brief Overload constructor.
     *
     * This constructor is used to define constant Attribute type.
     *
     * @param other The value to be passed in when defining Attribute.
     */
    Attributes(const Attributes &other) = delete;

    /**
     * @brief Overload operator.
     *
     * @param other The value to be compared.
     */
    Attributes &operator=(const Attributes &other) = delete;

    /**
     * @brief Overload constructor.
     *
     * @param other The value to be passed in when defining Attribute.
     */
    Attributes(Attributes &&other) noexcept;

    /**
     * @brief Overload operator.
     *
     * @param other The value to be compared.
     */
    Attributes &operator=(Attributes &&other) noexcept;

    /**
     * @brief Deconstructor.
     */
    virtual ~Attributes();

    /**
     * @brief Set bool value.
     *
     * @param key The attribute key.
     * @param value The bool value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetBoolValue(AttributeKey key, bool value);

    /**
     * @brief Set uint64 value.
     *
     * @param key The attribute key.
     * @param value The uint64_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint64Value(AttributeKey key, uint64_t value);

    /**
     * @brief Set uint32_t value.
     *
     * @param key The attribute key.
     * @param value The uint32_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint32Value(AttributeKey key, uint32_t value);

    /**
     * @brief Set uint16_t value.
     *
     * @param key The attribute key.
     * @param value The uint16_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint16Value(AttributeKey key, uint16_t value);

    /**
     * @brief Set uint8_t value.
     *
     * @param key The attribute key.
     * @param value The uint8_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint8Value(AttributeKey key, uint8_t value);

    /**
     * @brief Set int32_t value.
     *
     * @param key The attribute key.
     * @param value The int32_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetInt32Value(AttributeKey key, int32_t value);

    /**
     * @brief Set int64_t value.
     *
     * @param key The attribute key.
     * @param value The int64_t value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetInt64Value(AttributeKey key, int64_t value);

    /**
     * @brief Set string value.
     *
     * @param key The attribute key.
     * @param value The string.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetStringValue(AttributeKey key, const std::string &value);

    /**
     * @brief Set Attributes value.
     *
     * @param key The attribute key.
     * @param value The attributes type value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetAttributesValue(AttributeKey key, const Attributes &value);
    bool SetAttributesArrayValue(AttributeKey key, const std::vector<Attributes> &array);

    /**
     * @brief Set vector<uint64_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint64_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint64ArrayValue(AttributeKey key, const std::vector<uint64_t> &value);

    /**
     * @brief Set vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint32_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint32ArrayValue(AttributeKey key, const std::vector<uint32_t> &value);

    /**
     * @brief Set vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint32_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetInt32ArrayValue(AttributeKey key, const std::vector<int32_t> &value);

    /**
     * @brief Set vector<uint16_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint16_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint16ArrayValue(AttributeKey key, const std::vector<uint16_t> &value);

    /**
     * @brief Set vector<uint8_t> value.
     *
     * @param key The attribute key.
     * @param value The vector<uint8_t> value.
     * @return Return success or not(true:success; false:failed).
     */
    bool SetUint8ArrayValue(AttributeKey key, const std::vector<uint8_t> &value);

    /**
     * @brief Get bool value.
     *
     * @param key The attribute key.
     * @param value Return bool value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetBoolValue(AttributeKey key, bool &value) const;

    /**
     * @brief Get uint64_t value.
     *
     * @param key The attribute key.
     * @param value Return uint64_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint64Value(AttributeKey key, uint64_t &value) const;

    /**
     * @brief Get uint32_t value.
     *
     * @param key The attribute key.
     * @param value Return uint32_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint32Value(AttributeKey key, uint32_t &value) const;

    /**
     * @brief Get uint16_t value.
     *
     * @param key The attribute key.
     * @param value Return uint16_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint16Value(AttributeKey key, uint16_t &value) const;

    /**
     * @brief Get uint8_t value.
     *
     * @param key The attribute key.
     * @param value Return uint8_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint8Value(AttributeKey key, uint8_t &value) const;

    /**
     * @brief Get int32_t value.
     *
     * @param key The attribute key.
     * @param value Return int32_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetInt32Value(AttributeKey key, int32_t &value) const;

    /**
     * @brief Get int64_t value.
     *
     * @param key The attribute key.
     * @param value Return int64_t value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetInt64Value(AttributeKey key, int64_t &value) const;

    /**
     * @brief Get string value.
     *
     * @param key The attribute key.
     * @param value Return string corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetStringValue(AttributeKey key, std::string &value) const;

    /**
     * @brief Get vector<uint64_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint64_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint64ArrayValue(AttributeKey key, std::vector<uint64_t> &value) const;

    /**
     * @brief Get vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint32_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint32ArrayValue(AttributeKey key, std::vector<uint32_t> &value) const;

    /**
     * @brief Get vector<uint32_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint32_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetInt32ArrayValue(AttributeKey key, std::vector<int32_t> &value) const;

    /**
     * @brief Get vector<uint16_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint16_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint16ArrayValue(AttributeKey key, std::vector<uint16_t> &value) const;

    /**
     * @brief Get vector<uint8_t> value.
     *
     * @param key The attribute key.
     * @param value Return vector<uint8_t> value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetUint8ArrayValue(AttributeKey key, std::vector<uint8_t> &value) const;

    /**
     * @brief Get Attributes value.
     *
     * @param key The attribute key.
     * @param value Return Attributes value corresponding to key.
     * @return Return success or not(true:success; false:failed).
     */
    bool GetAttributesValue(AttributeKey key, Attributes &value) const;

    bool GetAttributesArrayValue(AttributeKey key, std::vector<Attributes> &array) const;

    /**
     * @brief Serialize the Attribute object.
     *
     * @return Return serialized Attribute object.
     */
    std::vector<uint8_t> Serialize() const;

    /**
     * @brief Get all keys of Attribute.
     *
     * @return Return all keys of Attribute.
     */
    std::vector<AttributeKey> GetKeys() const;

    /**
     * @brief Is specific attribute setted.
     *
     * @return Return is specific attribute setted.
     */
    bool HasAttribute(AttributeKey key) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_ {nullptr};
};
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS

#endif // IAM_ATTRIBUTES_H
