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

#include "attributes_test.h"

#include <climits>

#include "attributes.h"
#include "iam_common_defines.h"

#include "iam_logger.h"
#include "securec.h"

#define LOG_TAG "USER_AUTH_SA"
#define LOG_FILE_ID LOG_FILE_ATTRIBUTES

namespace OHOS {
namespace UserIam {
namespace UserAuth {
using namespace testing;
using namespace testing::ext;

void AttributesTest::SetUpTestCase()
{
}

void AttributesTest::TearDownTestCase()
{
}

void AttributesTest::SetUp()
{
}

void AttributesTest::TearDown()
{
}

HWTEST_F(AttributesTest, AttributesInit, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_EQ(attrs.Serialize().size(), 0U);
}

HWTEST_F(AttributesTest, AttributesSerialize, TestSize.Level0)
{
    const std::vector<Attributes::AttributeKey> desired = {Attributes::ATTR_RESULT_CODE, Attributes::ATTR_SIGNATURE,
        Attributes::ATTR_TEMPLATE_ID_LIST, Attributes::ATTR_REMAIN_TIMES, Attributes::ATTR_FREEZING_TIME,
        Attributes::ATTR_SCHEDULE_ID, Attributes::ATTR_SCHEDULE_MODE, Attributes::ATTR_CREDENTIAL_DIGEST};

    Attributes attrs;

    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false));
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, UINT64_MAX));
    EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, {1, 3, 5, 7, 9}));
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, UINT32_MAX));
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_CREDENTIAL_DIGEST, UINT16_MAX));
    EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, {2, 4, 6, 8, 10}));
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_TEMPLATE_ID_LIST, "iam"));

    EXPECT_THAT(attrs.GetKeys(), ElementsAreArray(desired));
    auto buff = attrs.Serialize();
    Attributes attrs2(buff);
    EXPECT_THAT(attrs2.GetKeys(), ElementsAreArray(desired));

    bool boolValue;
    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_RESULT_CODE, boolValue));
    EXPECT_EQ(boolValue, true);

    EXPECT_TRUE(attrs2.GetBoolValue(Attributes::ATTR_SIGNATURE, boolValue));
    EXPECT_EQ(boolValue, false);

    uint64_t u64Value;
    EXPECT_TRUE(attrs2.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, u64Value));
    EXPECT_EQ(u64Value, UINT64_MAX);

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrs2.GetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));
    EXPECT_THAT(u32Vector, ElementsAre(1, 3, 5, 7, 9));

    uint32_t u32Value;
    EXPECT_TRUE(attrs2.GetUint32Value(Attributes::ATTR_SCHEDULE_MODE, u32Value));
    EXPECT_EQ(u32Value, UINT32_MAX);

    uint16_t u16Value;
    EXPECT_TRUE(attrs2.GetUint16Value(Attributes::ATTR_CREDENTIAL_DIGEST, u16Value));
    EXPECT_EQ(u16Value, UINT16_MAX);

    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrs2.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, u64Vector));
    EXPECT_THAT(u64Vector, ElementsAre(2, 4, 6, 8, 10));

    std::string str;
    EXPECT_TRUE(attrs2.GetStringValue(Attributes::ATTR_TEMPLATE_ID_LIST, str));
    EXPECT_EQ(str, "iam");
}

HWTEST_F(AttributesTest, AttributesBoolValue, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs.SetBoolValue(Attributes::ATTR_SIGNATURE, false));

    bool value1;
    bool value2;
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetBoolValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1);
    EXPECT_FALSE(value2);
}

HWTEST_F(AttributesTest, AttributesUint64Value, TestSize.Level0)
{
    Attributes attrs;
    uint64_t value1;
    uint64_t value2;
    EXPECT_FALSE(attrs.GetUint64Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_FALSE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, value2));

    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_RESULT_CODE, UINT32_MAX));
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_SIGNATURE, UINT64_MAX));

    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, UINT32_MAX);
    EXPECT_EQ(value2, UINT64_MAX);
}

HWTEST_F(AttributesTest, AttributesUint32Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_RESULT_CODE, UINT16_MAX));
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_SIGNATURE, UINT32_MAX));

    uint32_t value1;
    uint32_t value2;
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT16_MAX);
    EXPECT_TRUE(value2 == UINT32_MAX);
}

HWTEST_F(AttributesTest, AttributesUint16Value, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_RESULT_CODE, UINT8_MAX));
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_SIGNATURE, UINT16_MAX));

    uint16_t value1;
    uint16_t value2;
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(value1 == UINT8_MAX);
    EXPECT_TRUE(value2 == UINT16_MAX);
}

HWTEST_F(AttributesTest, AttributesUint8Value, TestSize.Level0)
{
    Attributes attrs;

    uint8_t value1;
    uint8_t value2;
    EXPECT_FALSE(attrs.GetUint8Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_FALSE(attrs.GetUint8Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_TRUE(attrs.SetUint8Value(Attributes::ATTR_RESULT_CODE, 0));
    EXPECT_TRUE(attrs.SetUint8Value(Attributes::ATTR_SIGNATURE, UINT8_MAX));

    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetUint8Value(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, 0);
    EXPECT_EQ(value2, UINT8_MAX);
}

HWTEST_F(AttributesTest, AttributesStringValue, TestSize.Level0)
{
    Attributes attrs;
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_RESULT_CODE, "hello iam"));
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_SIGNATURE, ""));

    std::string value1;
    std::string value2;
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_RESULT_CODE, value1));
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_SIGNATURE, value2));
    EXPECT_EQ(value1, "hello iam");
    EXPECT_EQ(value2, "");
}

HWTEST_F(AttributesTest, AttributesUint64ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint64_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT64_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint64_t> out;
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }

    {
        Attributes attrs;
        std::vector<uint64_t> array;
        EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint32ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint32_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT32_MAX - i);
        }

        std::vector<uint32_t> out;
        EXPECT_FALSE(attrs.GetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint32_t> array;
        EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint16ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint16_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(UINT16_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint16_t> out;
        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint16_t> array;
        EXPECT_TRUE(attrs.SetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesUint8ByteArray, TestSize.Level0)
{
    {
        constexpr int SIZE = 8192;

        Attributes attrs;
        std::vector<uint8_t> array;
        array.reserve(SIZE);
        for (int i = 0; i < SIZE; i++) {
            array.push_back(i);
        }
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        std::vector<uint8_t> out;
        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, out));
        EXPECT_THAT(out, ElementsAreArray(array));
    }
    {
        Attributes attrs;
        std::vector<uint8_t> array;
        EXPECT_TRUE(attrs.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));

        EXPECT_TRUE(attrs.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, array));
        EXPECT_TRUE(array.empty());
    }
}

HWTEST_F(AttributesTest, AttributesDeserializeMismatch, TestSize.Level0)
{
    const std::vector<uint8_t> raw = {0, 0, 0, 0, 1, 0, 0, 0, 1, 2, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0,
        0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 40, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0,
        0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 0, 5, 0, 0, 0, 4, 0, 0,
        0, 255, 255, 255, 255, 6, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 7, 0, 0, 0, 4, 0, 0, 0,
        105, 97, 109, 0};

    Attributes attrs(raw);
    {
        bool value;
        EXPECT_FALSE(attrs.GetBoolValue(Attributes::ATTR_TEMPLATE_ID_LIST, value));
    }
    {
        uint16_t value;
        EXPECT_FALSE(attrs.GetUint16Value(Attributes::ATTR_TEMPLATE_ID_LIST, value));
    }
}

HWTEST_F(AttributesTest, AttributesEmptyArrays, TestSize.Level0)
{
    Attributes attrs1;
    bool value = true;
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_RESULT_CODE, value));

    std::vector<uint64_t> u64Vector;
    EXPECT_TRUE(attrs1.SetUint64ArrayValue(Attributes::ATTR_SCHEDULE_ID, u64Vector));

    std::vector<uint32_t> u32Vector;
    EXPECT_TRUE(attrs1.SetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));

    std::vector<uint16_t> u16Vector;
    EXPECT_FALSE(attrs1.GetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, u16Vector));
    EXPECT_TRUE(attrs1.SetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, u16Vector));

    std::vector<uint8_t> u8Vector;
    EXPECT_TRUE(attrs1.SetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, u8Vector));

    auto buff = attrs1.Serialize();
    EXPECT_FALSE(buff.empty());
    Attributes attrs2(buff);
    EXPECT_TRUE(attrs1.GetBoolValue(Attributes::ATTR_RESULT_CODE, value));
    EXPECT_TRUE(value);

    EXPECT_TRUE(attrs1.GetUint64ArrayValue(Attributes::ATTR_SCHEDULE_ID, u64Vector));
    EXPECT_THAT(u64Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint32ArrayValue(Attributes::ATTR_REMAIN_TIMES, u32Vector));
    EXPECT_THAT(u32Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, u16Vector));
    EXPECT_THAT(u16Vector, IsEmpty());

    EXPECT_TRUE(attrs1.GetUint8ArrayValue(Attributes::ATTR_FREEZING_TIME, u8Vector));
    EXPECT_THAT(u8Vector, IsEmpty());
}

HWTEST_F(AttributesTest, AttributesCopyAndMove, TestSize.Level0)
{
    EXPECT_FALSE(std::is_copy_assignable<Attributes>::value);
    EXPECT_FALSE(std::is_copy_constructible<Attributes>::value);

    const std::vector<uint8_t> raw = {0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 255,
        255, 255, 255, 3, 0, 0, 0, 8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 4, 0, 0, 0, 4, 0, 0, 0, 105, 97,
        109, 0, 5, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 5, 0, 0, 0, 7, 0, 0, 0, 9, 0, 0, 0, 6, 0, 0, 0, 40, 0,
        0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0,
        0, 0, 0, 0, 0};
    Attributes attrs1(raw);

    EXPECT_THAT(attrs1.Serialize(), ElementsAreArray(raw));

    Attributes attrs2 = std::move(attrs1);

    EXPECT_EQ(attrs1.Serialize().size(), 0U);
    EXPECT_THAT(attrs2.Serialize(), ElementsAreArray(raw));
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray, TestSize.Level0)
{
    Attributes attrs1;
    Attributes attrs2;
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs1.SetBoolValue(Attributes::ATTR_SCHEDULE_ID, false));
    EXPECT_TRUE(attrs2.SetBoolValue(Attributes::ATTR_RESULT_CODE, true));
    EXPECT_TRUE(attrs2.SetBoolValue(Attributes::ATTR_SCHEDULE_ID, false));

    std::vector<Attributes> attrsArray;
    attrsArray.push_back(Attributes(attrs1.Serialize()));
    attrsArray.push_back(Attributes(attrs2.Serialize()));

    Attributes setAttrs;
    EXPECT_TRUE(setAttrs.SetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrsArray));

    std::vector<uint8_t> data = setAttrs.Serialize();
    EXPECT_TRUE(data.size() > 0);

    Attributes getAttrs(data);
    std::vector<Attributes> getAttrsArray;
    EXPECT_TRUE(getAttrs.GetAttributesArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, getAttrsArray));

    ASSERT_EQ(getAttrsArray.size(), 2);
    std::vector<uint8_t> serializedAttrs1 = attrs1.Serialize();
    std::vector<uint8_t> serializedAttrs2 = attrs2.Serialize();

    std::vector<uint8_t> serializedOutAttrs1 = getAttrsArray[0].Serialize();
    std::vector<uint8_t> serializedOutAttrs2 = getAttrsArray[1].Serialize();

    EXPECT_TRUE(serializedAttrs1 == serializedOutAttrs1);
    EXPECT_TRUE(serializedAttrs2 == serializedOutAttrs2);
}

HWTEST_F(AttributesTest, AttributesSetAndGetAttributesArray01, TestSize.Level0)
{
    Attributes attrs1;
    int64_t value1 = 1;
    int64_t value2 = 2;
    EXPECT_EQ(attrs1.SetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, value2), true);
    EXPECT_EQ(attrs1.GetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, value1), true);
    EXPECT_EQ(value1, value2);

    Attributes setAttrs;
    Attributes attrs2;
    std::vector<int32_t> array2;
    EXPECT_EQ(setAttrs.GetInt32ArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, array2), false);
    EXPECT_EQ(setAttrs.GetAttributesValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrs2), false);
    EXPECT_EQ(setAttrs.SetAttributesValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrs1), true);
    EXPECT_EQ(setAttrs.GetAttributesValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, attrs2), true);

    std::vector<int32_t> array1;
    array1.push_back(1);
    EXPECT_EQ(setAttrs.SetInt32ArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, array1), true);
    EXPECT_EQ(setAttrs.GetInt32ArrayValue(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, array2), true);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint64Value, TestSize.Level0)
{
    Attributes attrs;
    uint64_t encode_val64 = 0x0102030405060708;
    uint64_t encode_val32 = 0x01020304;

    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_SIGNATURE, encode_val64));
    EXPECT_TRUE(attrs.SetUint64Value(Attributes::ATTR_RESULT_CODE, encode_val32));
     
    uint64_t decode_val64;
    uint64_t decode_val32;

    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_SIGNATURE, decode_val64));
    EXPECT_TRUE(attrs.GetUint64Value(Attributes::ATTR_RESULT_CODE, decode_val32));

    EXPECT_EQ(encode_val64, decode_val64);
    EXPECT_EQ(encode_val32, decode_val32);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint32Value, TestSize.Level0)
{
    Attributes attrs;
    uint32_t encode_val32 = 0x01020304;
    uint32_t encode_val16 = 0x0102;

    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_SIGNATURE, encode_val32));
    EXPECT_TRUE(attrs.SetUint32Value(Attributes::ATTR_RESULT_CODE, encode_val16));
    
    uint32_t decode_val32;
    uint32_t decode_val16;

    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_SIGNATURE, decode_val32));
    EXPECT_TRUE(attrs.GetUint32Value(Attributes::ATTR_RESULT_CODE, decode_val16));

    EXPECT_EQ(encode_val32, decode_val32);
    EXPECT_EQ(encode_val16, decode_val16);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint16Value, TestSize.Level0)
{
    Attributes attrs;
    uint16_t encode_val16 = 0x0102;
    uint16_t encode_val8 = 0x01;

    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_SIGNATURE, encode_val16));
    EXPECT_TRUE(attrs.SetUint16Value(Attributes::ATTR_RESULT_CODE, encode_val8));

    uint16_t decode_val16;
    uint16_t decode_val8;

    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_SIGNATURE, decode_val16));
    EXPECT_TRUE(attrs.GetUint16Value(Attributes::ATTR_RESULT_CODE, decode_val8));

    EXPECT_EQ(encode_val16, decode_val16);
    EXPECT_EQ(encode_val8, decode_val8);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt64Value, TestSize.Level0)
{
    Attributes attrs;
    int64_t encode_val64 = 0x0102030405060708;
    int64_t encode_val32 = 0x01020304;

    EXPECT_TRUE(attrs.SetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, encode_val64));
    EXPECT_TRUE(attrs.SetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, encode_val32));
    
    int64_t decode_val64;
    int64_t decode_val32;

    EXPECT_TRUE(attrs.GetInt64Value(Attributes::ATTR_EXECUTOR_REGISTER_INFO_LIST, decode_val64));
    EXPECT_TRUE(attrs.GetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, decode_val32));

    EXPECT_EQ(encode_val64, decode_val64);
    EXPECT_EQ(encode_val32, decode_val32);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt32Value, TestSize.Level0)
{
    Attributes attrs;
    int32_t encode_val32 = 0x01020304;
    int32_t encode_val16 = 0x0102;

    EXPECT_TRUE(attrs.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, encode_val32));
    EXPECT_TRUE(attrs.SetInt32Value(Attributes::ATTR_TIP_INFO, encode_val16));

    int32_t decode_val32;
    int32_t decode_val16;

    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, decode_val32));
    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_TIP_INFO, decode_val16));

    EXPECT_EQ(encode_val32, decode_val32);
    EXPECT_EQ(encode_val16, decode_val16);
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint64Array, TestSize.Level0)
{
    {
        Attributes attrs_outsize;
        constexpr int ENCODE_ARRAY_OUT_SIZE = 81921;
        std::vector<uint64_t> encode_outsize_array;
        encode_outsize_array.reserve(ENCODE_ARRAY_OUT_SIZE);
        for (int i = 0; i < ENCODE_ARRAY_OUT_SIZE; i++) {
            encode_outsize_array.push_back(UINT64_MAX - i);
        }
        EXPECT_FALSE(attrs_outsize.SetUint64ArrayValue(Attributes::ATTR_LOCKED_TEMPLATES, encode_outsize_array));
    }

    {
        Attributes attrs_empty;
        std::vector<uint64_t> encode_empty_array;
        std::vector<uint64_t> decode_empty_array;
        EXPECT_TRUE(attrs_empty.SetUint64ArrayValue(Attributes::ATTR_LOCKED_TEMPLATES, encode_empty_array));
        EXPECT_TRUE(attrs_empty.GetUint64ArrayValue(Attributes::ATTR_LOCKED_TEMPLATES, decode_empty_array));
        EXPECT_THAT(encode_empty_array, decode_empty_array);
    }

    {
        Attributes attrs;
        constexpr int ARRAY_SIZE = 1024;
        std::vector<uint64_t> encode_array;
        std::vector<uint64_t> decode_array;
        encode_array.reserve(ARRAY_SIZE);
        for (int i = 0; i < ARRAY_SIZE; i++) {
            encode_array.push_back(UINT64_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint64ArrayValue(Attributes::ATTR_LOCKED_TEMPLATES, encode_array));
        EXPECT_TRUE(attrs.GetUint64ArrayValue(Attributes::ATTR_LOCKED_TEMPLATES, decode_array));
        EXPECT_THAT(encode_array, decode_array);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint32Array, TestSize.Level0)
{
    {
        Attributes attrs_outsize;
        constexpr int ENCODE_ARRAY_OUT_SIZE = 81921;
        std::vector<uint32_t> encode_outsize_array;
        encode_outsize_array.reserve(ENCODE_ARRAY_OUT_SIZE);
        for (int i = 0; i < ENCODE_ARRAY_OUT_SIZE; i++) {
            encode_outsize_array.push_back(UINT32_MAX - i);
        }
        EXPECT_FALSE(attrs_outsize.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, encode_outsize_array));
    }

    {
        Attributes attrs_empty;
        std::vector<uint32_t> encode_empty_array;
        std::vector<uint32_t> decode_empty_array;
        EXPECT_TRUE(attrs_empty.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, encode_empty_array));
        EXPECT_TRUE(attrs_empty.GetUint32ArrayValue(Attributes::ATTR_KEY_LIST, decode_empty_array));
        EXPECT_THAT(encode_empty_array, decode_empty_array);
    }

    {
        Attributes attrs;
        constexpr int ARRAY_SIZE = 1024;
        std::vector<uint32_t> encode_array;
        std::vector<uint32_t> decode_array;
        encode_array.reserve(ARRAY_SIZE);
        for (int i = 0; i < ARRAY_SIZE; i++) {
            encode_array.push_back(UINT32_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST, encode_array));
        EXPECT_TRUE(attrs.GetUint32ArrayValue(Attributes::ATTR_KEY_LIST, decode_array));
        EXPECT_THAT(encode_array, decode_array);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeUint16Array, TestSize.Level0)
{
    {
        Attributes attrs_outsize;
        constexpr int ENCODE_ARRAY_OUT_SIZE = 81921;
        std::vector<uint16_t> encode_outsize_array;
        encode_outsize_array.reserve(ENCODE_ARRAY_OUT_SIZE);
        for (int i = 0; i < ENCODE_ARRAY_OUT_SIZE; i++) {
            encode_outsize_array.push_back(UINT16_MAX - i);
        }
        EXPECT_FALSE(attrs_outsize.SetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, encode_outsize_array));
    }

    {
        Attributes attrs_empty;
        std::vector<uint16_t> encode_empty_array;
        std::vector<uint16_t> decode_empty_array;
        EXPECT_TRUE(attrs_empty.SetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, encode_empty_array));
        EXPECT_TRUE(attrs_empty.GetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, decode_empty_array));
        EXPECT_THAT(encode_empty_array, decode_empty_array);
    }

    {
        Attributes attrs;
        constexpr int ARRAY_SIZE = 1024;
        std::vector<uint16_t> encode_array;
        std::vector<uint16_t> decode_array;
        encode_array.reserve(ARRAY_SIZE);
        for (int i = 0; i < ARRAY_SIZE; i++) {
            encode_array.push_back(UINT16_MAX - i);
        }
        EXPECT_TRUE(attrs.SetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, encode_array));
        EXPECT_TRUE(attrs.GetUint16ArrayValue(Attributes::ATTR_TEMPLATE_ID_LIST, decode_array));
        EXPECT_THAT(encode_array, decode_array);
    }
}

HWTEST_F(AttributesTest, AttributesEncodeAndDecodeInt32Array, TestSize.Level0)
{
    {
        Attributes attrs_outsize;
        constexpr int ENCODE_ARRAY_OUT_SIZE = 81921;
        std::vector<int32_t> encode_outsize_array;
        encode_outsize_array.reserve(ENCODE_ARRAY_OUT_SIZE);
        for (int i = 0; i < ENCODE_ARRAY_OUT_SIZE; i++) {
            encode_outsize_array.push_back(INT32_MAX - i);
        }
        EXPECT_FALSE(attrs_outsize.SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, encode_outsize_array));
    }

    {
        Attributes attrs_empty;
        std::vector<int32_t> encode_empty_array;
        std::vector<int32_t> decode_empty_array;
        EXPECT_TRUE(attrs_empty.SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, encode_empty_array));
        EXPECT_TRUE(attrs_empty.GetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, decode_empty_array));
        EXPECT_THAT(encode_empty_array, decode_empty_array);
    }

    {
        Attributes attrs;
        constexpr int ARRAY_SIZE = 1024;
        std::vector<int32_t> encode_array;
        std::vector<int32_t> decode_array;
        encode_array.reserve(ARRAY_SIZE);
        for (int i = 0; i < ARRAY_SIZE; i++) {
            encode_array.push_back(INT32_MAX - i);
        }
        EXPECT_TRUE(attrs.SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, encode_array));
        EXPECT_TRUE(attrs.GetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, decode_array));
        EXPECT_THAT(encode_array, decode_array);
    }
}

HWTEST_F(AttributesTest, AttributesSerializeAndDeserialize01, TestSize.Level0)
{
    const uint64_t U64_VAL = 0x0102030405060708;
    const uint32_t U32_VAL = 0x01020304;
    const uint16_t U16_VAL = 0x0102;
    const int32_t I32_VAL = 0x01020304;
    Attributes attrs_serial;
    EXPECT_TRUE(attrs_serial.SetUint64Value(Attributes::ATTR_SCHEDULE_ID, U64_VAL));
    EXPECT_TRUE(attrs_serial.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, U32_VAL));
    EXPECT_TRUE(attrs_serial.SetUint16Value(Attributes::ATTR_CREDENTIAL_DIGEST, U16_VAL));
    EXPECT_TRUE(attrs_serial.SetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME,
    {U64_VAL, U64_VAL, U64_VAL, U64_VAL, U64_VAL}));
    EXPECT_TRUE(attrs_serial.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST,
    {U32_VAL, U32_VAL, U32_VAL, U32_VAL, U32_VAL}));
    EXPECT_TRUE(attrs_serial.SetInt32Value(Attributes::ATTR_REMAIN_TIMES, I32_VAL));
    EXPECT_TRUE(attrs_serial.SetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES,
    {I32_VAL, I32_VAL, I32_VAL, I32_VAL, I32_VAL}));
    int64_t test_int64_val = 100;
    EXPECT_TRUE(attrs_serial.SetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, test_int64_val));
    auto buffer = attrs_serial.Serialize();

    Attributes attrs_deserial(buffer);
    uint64_t u64_value;
    EXPECT_TRUE(attrs_deserial.GetUint64Value(Attributes::ATTR_SCHEDULE_ID, u64_value));
    EXPECT_EQ(u64_value, U64_VAL);
    uint32_t u32_value;
    EXPECT_TRUE(attrs_deserial.GetUint32Value(Attributes::ATTR_SCHEDULE_MODE, u32_value));
    EXPECT_EQ(u32_value, U32_VAL);
    uint16_t u16_value;
    EXPECT_TRUE(attrs_deserial.GetUint16Value(Attributes::ATTR_CREDENTIAL_DIGEST, u16_value));
    EXPECT_EQ(u16_value, U16_VAL);
    std::vector<uint64_t> u64_vector;
    EXPECT_TRUE(attrs_deserial.GetUint64ArrayValue(Attributes::ATTR_FREEZING_TIME, u64_vector));
    EXPECT_THAT(u64_vector, ElementsAre(U64_VAL, U64_VAL, U64_VAL, U64_VAL, U64_VAL));
    std::vector<uint32_t> u32_vector;
    EXPECT_TRUE(attrs_deserial.GetUint32ArrayValue(Attributes::ATTR_KEY_LIST, u32_vector));
    EXPECT_THAT(u32_vector, ElementsAre(U32_VAL, U32_VAL, U32_VAL, U32_VAL, U32_VAL));
    int32_t int32_value;
    EXPECT_TRUE(attrs_deserial.GetInt32Value(Attributes::ATTR_REMAIN_TIMES, int32_value));
    EXPECT_EQ(int32_value, I32_VAL);
    std::vector<int32_t> int32_vector;
    EXPECT_TRUE(attrs_deserial.GetInt32ArrayValue(Attributes::ATTR_AUTH_TYPES, int32_vector));
    EXPECT_THAT(int32_vector, ElementsAre(I32_VAL, I32_VAL, I32_VAL, I32_VAL, I32_VAL));
    int64_t int64_value;
    EXPECT_TRUE(attrs_deserial.GetInt64Value(Attributes::ATTR_PIN_EXPIRED_INFO, int64_value));
    EXPECT_EQ(int64_value, 100);
}

HWTEST_F(AttributesTest, AttributesSerializeAndDeserialize02, TestSize.Level0)
{
    const uint32_t U32_VAL = 0x01020304;
    const uint8_t U8_VAL = 0x01;
    Attributes attrs_serial;
    EXPECT_TRUE(attrs_serial.SetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, true));
    EXPECT_TRUE(attrs_serial.SetBoolValue(Attributes::ATTR_MSG_ACK, false));
    EXPECT_TRUE(attrs_serial.SetUint32Value(Attributes::ATTR_SCHEDULE_MODE, U32_VAL));
    EXPECT_TRUE(attrs_serial.SetUint32ArrayValue(Attributes::ATTR_KEY_LIST,
    {U32_VAL, U32_VAL, U32_VAL, U32_VAL, U32_VAL}));
    EXPECT_TRUE(attrs_serial.SetStringValue(Attributes::ATTR_CALLER_NAME, "iam_unit_test"));
    EXPECT_TRUE(attrs_serial.SetUint8Value(Attributes::ATTR_ROOT, U8_VAL));
    EXPECT_TRUE(attrs_serial.SetUint8ArrayValue(Attributes::ATTR_DATA,
    {U8_VAL, U8_VAL, U8_VAL, U8_VAL, U8_VAL}));
    auto buffer = attrs_serial.Serialize();

    Attributes attrs_deserial(buffer);
    bool bool_valt;
    EXPECT_TRUE(attrs_deserial.GetBoolValue(Attributes::ATTR_END_AFTER_FIRST_FAIL, bool_valt));
    EXPECT_EQ(bool_valt, true);

    bool bool_valf;
    EXPECT_TRUE(attrs_deserial.GetBoolValue(Attributes::ATTR_MSG_ACK, bool_valf));
    EXPECT_EQ(bool_valf, false);

    uint32_t u32_value;
    EXPECT_TRUE(attrs_deserial.GetUint32Value(Attributes::ATTR_SCHEDULE_MODE, u32_value));
    EXPECT_EQ(u32_value, U32_VAL);

    std::vector<uint32_t> u32_vector;
    EXPECT_TRUE(attrs_deserial.GetUint32ArrayValue(Attributes::ATTR_KEY_LIST, u32_vector));
    EXPECT_THAT(u32_vector, ElementsAre(U32_VAL, U32_VAL, U32_VAL, U32_VAL, U32_VAL));

    std::string str_value;
    EXPECT_TRUE(attrs_deserial.GetStringValue(Attributes::ATTR_CALLER_NAME, str_value));
    EXPECT_EQ(str_value, "iam_unit_test");

    uint8_t u8_val;
    EXPECT_TRUE(attrs_deserial.GetUint8Value(Attributes::ATTR_ROOT, u8_val));
    EXPECT_EQ(u8_val, U8_VAL);

    std::vector<uint8_t> u8_vector;
    EXPECT_TRUE(attrs_deserial.GetUint8ArrayValue(Attributes::ATTR_DATA, u8_vector));
    EXPECT_THAT(u8_vector, ElementsAre(U8_VAL, U8_VAL, U8_VAL, U8_VAL, U8_VAL));
}

HWTEST_F(AttributesTest, AttributesRawSerializeTest01, TestSize.Level0)
{
    std::vector<uint8_t> raw = {160, 134, 1, 0, 1, 0, 0, 0, 255, 175, 134,
        1, 0, 14, 0, 0, 0, 105, 97, 109, 95, 117, 110, 105, 116, 95, 116,
        101, 115, 116, 0, 180, 134, 1, 0, 5, 0, 0, 0, 255, 255,
        255, 255, 255, 182, 134, 1, 0, 4, 0, 0, 0, 255, 255, 255,
        255, 197, 134, 1, 0, 20, 0, 0, 0, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 198, 134, 1, 0, 1, 0, 0, 0, 1, 213, 134, 1, 0, 1,
        0, 0, 0, 0};
    
    Attributes attrs(raw);
    std::vector<uint8_t> buffer = attrs.Serialize();
    for (int i = 0; i < buffer.size(); i++) {
        EXPECT_THAT(raw[i], buffer[i]);
    }
}

HWTEST_F(AttributesTest, AttributesRawSerializeTest03, TestSize.Level0)
{
    std::vector<uint8_t> raw = {169, 134, 1, 0, 4, 0, 0, 0, 255, 255, 255,
        127, 170, 134, 1, 0, 40, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 177, 134, 1, 0,
        8, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 182,
        134, 1, 0, 4, 0, 0, 0, 255, 255, 255, 255, 197,
        134, 1, 0, 20, 0, 0, 0, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 210, 134, 1, 0, 2, 0, 0, 0, 255,
        255, 234, 134, 1, 0, 20, 0, 0, 0, 255, 255, 255,
        127, 255, 255, 255, 127, 255, 255, 255,
        127, 255, 255, 255, 127, 255, 255, 255,
        127, 243, 134, 1, 0, 8, 0, 0, 0, 100, 0, 0, 0, 0, 0, 0, 0};
    
    Attributes attrs(raw);
    std::vector<uint8_t> buffer = attrs.Serialize();
    for (int i = 0; i < buffer.size(); i++) {
        EXPECT_THAT(raw[i], buffer[i]);
    }
}

HWTEST_F(AttributesTest, AttributesTest01, TestSize.Level0)
{
    IAM_LOGI("AttributesTest01 begin\n");
    std::vector<uint8_t> extraInfo = {0};
    Attributes attribute = Attributes(extraInfo);
    extraInfo.resize(16);
    EXPECT_NO_THROW(extraInfo.resize(24));
    attribute.~Attributes();
    uint64_t attrValue = 0;
    bool returnBool = attribute.SetUint64Value(Attributes::ATTR_ROOT, attrValue);
    attribute.SetBoolValue(Attributes::ATTR_ROOT, returnBool);
    uint32_t uint32Value = 0;
    attribute.SetUint32Value(Attributes::ATTR_ROOT, uint32Value);
    uint16_t uint16Value = 0;
    attribute.SetUint16Value(Attributes::ATTR_ROOT, uint16Value);
    uint8_t uint8Value = 0;
    attribute.SetUint8Value(Attributes::ATTR_ROOT, uint8Value);
    int32_t int32Value = 0;
    attribute.SetInt32Value(Attributes::ATTR_ROOT, int32Value);
    int64_t int64Value = 0;
    attribute.SetInt64Value(Attributes::ATTR_ROOT, int64Value);
    std::string stringValue = "";
    attribute.SetStringValue(Attributes::ATTR_ROOT, stringValue);
    std::vector<uint64_t> uint64ArrayValue = {};
    attribute.SetUint64ArrayValue(Attributes::ATTR_ROOT, uint64ArrayValue);
    std::vector<uint32_t> uint32ArrayValue = {};
    attribute.SetUint32ArrayValue(Attributes::ATTR_ROOT, uint32ArrayValue);
    std::vector<uint16_t> uint16ArrayValue = {};
    attribute.SetUint16ArrayValue(Attributes::ATTR_ROOT, uint16ArrayValue);
    std::vector<uint8_t> uint8ArrayValue = {};
    attribute.SetUint8ArrayValue(Attributes::ATTR_ROOT, uint8ArrayValue);
    std::vector<int32_t> int32ArrayValue = {};
    attribute.SetInt32ArrayValue(Attributes::ATTR_ROOT, int32ArrayValue);
    Attributes AttributesValue = Attributes(extraInfo);
    attribute.SetAttributesValue(Attributes::ATTR_ROOT, AttributesValue);
    IAM_LOGI("AttributesTest01 end\n");
}

HWTEST_F(AttributesTest, AttributesTest02, TestSize.Level0)
{
    IAM_LOGI("AttributesTest02 begin\n");
    std::vector<uint8_t> extraInfo = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    Attributes attribute = Attributes(extraInfo);
    extraInfo.push_back(0);
    attribute = Attributes(extraInfo);
    attribute.HasAttribute(Attributes::ATTR_ROOT);
    attribute.~Attributes();
    bool returnBool = false;
    Attributes attributeValue = Attributes(extraInfo);
    std::vector<Attributes> array = {};
    returnBool = attribute.SetAttributesArrayValue(Attributes::ATTR_ROOT, array);
    attribute.GetAttributesArrayValue(Attributes::ATTR_ROOT, array);
    attribute.GetBoolValue(Attributes::ATTR_ROOT, returnBool);
    uint64_t uint64Value = 0;
    attribute.GetUint64Value(Attributes::ATTR_ROOT, uint64Value);
    uint32_t uint32Value = 0;
    attribute.GetUint32Value(Attributes::ATTR_ROOT, uint32Value);
    uint16_t uint16Value = 0;
    attribute.GetUint16Value(Attributes::ATTR_ROOT, uint16Value);
    uint8_t uint8Value = 0;
    attribute.GetUint8Value(Attributes::ATTR_ROOT, uint8Value);
    int32_t int32Value = 0;
    attribute.GetInt32Value(Attributes::ATTR_ROOT, int32Value);
    int64_t int64Value = 0;
    attribute.GetInt64Value(Attributes::ATTR_ROOT, int64Value);
    std::string stringValue = "";
    attribute.GetStringValue(Attributes::ATTR_ROOT, stringValue);
    std::vector<uint64_t> uint64ArrayValue = {};
    attribute.GetUint64ArrayValue(Attributes::ATTR_ROOT, uint64ArrayValue);
    std::vector<uint32_t> uint32ArrayValue = {};
    attribute.GetUint32ArrayValue(Attributes::ATTR_ROOT, uint32ArrayValue);
    std::vector<uint16_t> uint16ArrayValue = {};
    attribute.GetUint16ArrayValue(Attributes::ATTR_ROOT, uint16ArrayValue);
    std::vector<uint8_t> uint8ArrayValue = {};
    attribute.GetUint8ArrayValue(Attributes::ATTR_ROOT, uint8ArrayValue);
    std::vector<int32_t> int32ArrayValue = {};
    attribute.GetInt32ArrayValue(Attributes::ATTR_ROOT, int32ArrayValue);
    attribute.GetAttributesValue(Attributes::ATTR_ROOT, attributeValue);
    attribute.GetKeys();
    attribute.HasAttribute(Attributes::ATTR_ROOT);
    EXPECT_EQ(returnBool, false);
    IAM_LOGI("AttributesTest02 end\n");
}

HWTEST_F(AttributesTest, AttributesTest03, TestSize.Level0)
{
    IAM_LOGI("AttributesTest03 begin\n");
    std::vector<uint8_t> extraInfo = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    Attributes attribute = Attributes(extraInfo);
    const uint32_t MAX_ATTR_LENGTH = 81921;
    std::string stringValue = "123";
    stringValue.resize(MAX_ATTR_LENGTH, '1');
    extraInfo.resize(MAX_ATTR_LENGTH);
    uint64_t src = 0x123456789ABCDEF0;
    attribute.SetUint64Value(Attributes::ATTR_ROOT, src);
    attribute.SetUint8ArrayValue(Attributes::ATTR_ROOT, extraInfo);
    bool returnBool = attribute.SetStringValue(Attributes::ATTR_ROOT, stringValue);
    EXPECT_EQ(returnBool, false);
    IAM_LOGI("AttributesTest03 end\n");
}

HWTEST_F(AttributesTest, AttributesTestAuthScene_001, TestSize.Level0)
{
    IAM_LOGI("AttributesTestAuthScene_001 begin\n");
    Attributes attrs;
    int32_t authSceneValue = static_cast<int32_t>(AuthScene::AUTH_SCENE_WIDGET_AUTH_NO_DISTURB);
    EXPECT_TRUE(attrs.SetInt32Value(Attributes::ATTR_AUTH_SCENE, authSceneValue));
    
    int32_t retrievedValue = 0;
    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_AUTH_SCENE, retrievedValue));
    EXPECT_EQ(retrievedValue, authSceneValue);
    IAM_LOGI("AttributesTestAuthScene_001 end\n");
}

HWTEST_F(AttributesTest, AttributesTestAuthScene_002, TestSize.Level0)
{
    IAM_LOGI("AttributesTestAuthScene_002 begin\n");
    Attributes attrs;
    int32_t authSceneValue = static_cast<int32_t>(AuthScene::AUTH_SCENE_DEFAULT);
    EXPECT_TRUE(attrs.SetInt32Value(Attributes::ATTR_AUTH_SCENE, authSceneValue));
    
    int32_t retrievedValue = 0;
    EXPECT_TRUE(attrs.GetInt32Value(Attributes::ATTR_AUTH_SCENE, retrievedValue));
    EXPECT_EQ(retrievedValue, authSceneValue);
    IAM_LOGI("AttributesTestAuthScene_002 end\n");
}

HWTEST_F(AttributesTest, AttributesTestWidgetTitle_001, TestSize.Level0)
{
    IAM_LOGI("AttributesTestWidgetTitle_001 begin\n");
    Attributes attrs;
    std::string titleValue = "widget_auth_title";
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_WIDGET_TITLE, titleValue));
    
    std::string retrievedValue;
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_WIDGET_TITLE, retrievedValue));
    EXPECT_EQ(retrievedValue, titleValue);
    IAM_LOGI("AttributesTestWidgetTitle_001 end\n");
}

HWTEST_F(AttributesTest, AttributesTestWidgetTitle_002, TestSize.Level0)
{
    IAM_LOGI("AttributesTestWidgetTitle_002 begin\n");
    Attributes attrs;
    std::string titleValue = "";
    EXPECT_TRUE(attrs.SetStringValue(Attributes::ATTR_WIDGET_TITLE, titleValue));
    
    std::string retrievedValue;
    EXPECT_TRUE(attrs.GetStringValue(Attributes::ATTR_WIDGET_TITLE, retrievedValue));
    EXPECT_EQ(retrievedValue, titleValue);
    IAM_LOGI("AttributesTestWidgetTitle_002 end\n");
}
} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
