#ifndef _WASIX_VALUE_TYPE_H
#define _WASIX_VALUE_TYPE_H

#include <stdint.h>

typedef uint8_t wasix_value_type_t;

#define WASIX_VALUE_TYPE_I32 UINT8_C(0)
#define WASIX_VALUE_TYPE_I64 UINT8_C(1)
#define WASIX_VALUE_TYPE_F32 UINT8_C(2)
#define WASIX_VALUE_TYPE_F64 UINT8_C(3)
#define WASIX_VALUE_TYPE_V128 UINT8_C(4)

#endif
