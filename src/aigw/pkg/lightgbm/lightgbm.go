/*
 * SPDX-License-Identifier: MIT
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: lightgbm for decode length prediction
 * Create: 2025-5-13
 */

// Package lightgbm
package lightgbm

/*
#cgo LDFLAGS: -l_lightgbm -lstdc++ -lm -lpthread -fopenmp
#include <stdlib.h>
#include <stdio.h>
#include <LightGBM/c_api.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// BoosterParams booster params
type BoosterParams struct {
	ModelFile string
}

// Booster a booster
type Booster struct {
	handler          C.BoosterHandle
	predictDimension int32
	numIterations    int32
}

// NewBooster new a booster
func NewBooster(param BoosterParams) (*Booster, error) {
	// predict
	if len(param.ModelFile) == 0 {
		return nil, fmt.Errorf("new booster failed for invaild param %v", param)
	}
	booster := &Booster{}

	filename := C.CString(param.ModelFile)
	defer C.free(unsafe.Pointer(filename))
	res := C.LGBM_BoosterCreateFromModelfile(filename, (*C.int)(&booster.numIterations), &booster.handler)
	if int(res) != 0 {
		return nil, fmt.Errorf("LGBM_BoosterCreateFromModelfile failed for %s", C.GoString(C.LGBM_GetLastError()))
	}
	res = C.LGBM_BoosterGetNumClasses(booster.handler, (*C.int)(&booster.predictDimension))
	if int(res) != 0 {
		C.LGBM_BoosterFree(booster.handler)
		return nil, fmt.Errorf("LGBM_BoosterGetNumClasses failed for %s", C.GoString(C.LGBM_GetLastError()))
	}
	if booster.predictDimension <= 0 {
		C.LGBM_BoosterFree(booster.handler)
		return nil, fmt.Errorf("predictDimension is 0, cannot predict")
	}
	return booster, nil
}

// BoosterDestroy destroy a booster
func BoosterDestroy(booster *Booster) {
	if booster != nil && booster.handler != nil {
		C.LGBM_BoosterFree(booster.handler)
		booster.handler = nil
	}
}

// Predict result
func (b *Booster) Predict(features []float64) ([]float64, error) {
	if len(features) == 0 {
		return nil, fmt.Errorf("the length of features is 0")
	}

	rsp := make([]float64, b.predictDimension)
	if rsp == nil {
		return nil, fmt.Errorf("make slice failed")
	}

	var outLen int64 = 0
	res := C.LGBM_BoosterPredictForMat(b.handler, unsafe.Pointer(&features[0]), C.C_API_DTYPE_FLOAT64,
		C.int32_t(1), C.int32_t(len(features)), C.int(0), C.C_API_PREDICT_NORMAL,
		C.int(0), C.int(-1), C.CString(""), (*C.int64_t)(&outLen), (*C.double)(&rsp[0]))
	if int(res) != 0 {
		return nil, fmt.Errorf("predict failed for %s", C.GoString(C.LGBM_GetLastError()))
	}
	return rsp, nil
}
