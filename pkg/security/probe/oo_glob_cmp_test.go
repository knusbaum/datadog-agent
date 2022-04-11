// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
)

func TestGlobEquals(t *testing.T) {
	t.Run("no-match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Value:     "/abc/",
			ValueType: eval.PatternValueType,
		}

		b := &eval.StringEvaluator{
			Field: "field",
			EvalFnc: func(ctx *eval.Context) string {
				return "/2/abc/3"
			},
		}

		var ctx eval.Context
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringEquals(a, b, nil, state)
		assert.Empty(t, err)
		assert.False(t, e.Eval(&ctx).(bool))

		e, err = GlobCmp.StringEquals(b, a, nil, state)
		assert.Empty(t, err)
		assert.False(t, e.Eval(&ctx).(bool))
	})

	t.Run("match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Value:     "*/abc/*",
			ValueType: eval.PatternValueType,
		}

		b := &eval.StringEvaluator{
			Field: "field",
			EvalFnc: func(ctx *eval.Context) string {
				return "/2/abc/3"
			},
		}

		var ctx eval.Context
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringEquals(a, b, nil, state)
		assert.Empty(t, err)
		assert.True(t, e.Eval(&ctx).(bool))

		e, err = GlobCmp.StringEquals(b, a, nil, state)
		assert.Empty(t, err)
		assert.True(t, e.Eval(&ctx).(bool))
	})
}

func TestGlobContains(t *testing.T) {
	t.Run("no-match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Field: "field",
			EvalFnc: func(ctx *eval.Context) string {
				return "/2/abc/3"
			},
		}

		var values eval.StringValues
		values.AppendFieldValue(eval.FieldValue{Value: "/abc/", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "abc/*", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "*/abc", Type: eval.PatternValueType})

		b := &eval.StringValuesEvaluator{
			Values: values,
		}

		var ctx eval.Context
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringValuesContains(a, b, nil, state)
		assert.Empty(t, err)
		assert.False(t, e.Eval(&ctx).(bool))
	})

	t.Run("match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Field: "field",
			EvalFnc: func(ctx *eval.Context) string {
				return "/2/abc/3"
			},
		}

		var values eval.StringValues
		values.AppendFieldValue(eval.FieldValue{Value: "*/abc/*", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "abc", Type: eval.PatternValueType})

		b := &eval.StringValuesEvaluator{
			Values: values,
		}

		var ctx eval.Context
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringValuesContains(a, b, nil, state)
		assert.Empty(t, err)
		assert.True(t, e.Eval(&ctx).(bool))
	})
}

func TestGlobArrayMatches(t *testing.T) {
	t.Run("no-match", func(t *testing.T) {
		a := &eval.StringArrayEvaluator{
			Values: []string{"/2/abc/3"},
		}

		var values eval.StringValues
		values.AppendFieldValue(eval.FieldValue{Value: "abc", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "abc/*", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "*/abc", Type: eval.PatternValueType})

		b := &eval.StringValuesEvaluator{
			Values: values,
		}
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringArrayMatches(a, b, nil, state)
		assert.Empty(t, err)
		assert.False(t, e.Value)
	})

	t.Run("match", func(t *testing.T) {
		a := &eval.StringArrayEvaluator{
			Values: []string{"/2/abc/3"},
		}

		var values eval.StringValues
		values.AppendFieldValue(eval.FieldValue{Value: "*/abc/*", Type: eval.PatternValueType})
		values.AppendFieldValue(eval.FieldValue{Value: "abc", Type: eval.PatternValueType})

		b := &eval.StringValuesEvaluator{
			Values: values,
		}
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringArrayMatches(a, b, nil, state)
		assert.Empty(t, err)
		assert.True(t, e.Value)
	})
}

func TestGlobArrayContains(t *testing.T) {
	t.Run("no-match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Value:     "/abc/",
			ValueType: eval.PatternValueType,
		}

		b := &eval.StringArrayEvaluator{
			Values: []string{"/2/abc/3"},
		}
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringArrayContains(a, b, nil, state)
		assert.Empty(t, err)
		assert.False(t, e.Value)
	})

	t.Run("match", func(t *testing.T) {
		a := &eval.StringEvaluator{
			Value:     "*/abc/*",
			ValueType: eval.PatternValueType,
		}

		b := &eval.StringArrayEvaluator{
			Field:  "dont_forget_me_or_it_wont_compile_a",
			Values: []string{"/2/abc/3"},
		}
		state := eval.NewState(&model.Model{}, "", nil)

		e, err := GlobCmp.StringArrayContains(a, b, nil, state)
		assert.Empty(t, err)
		assert.True(t, e.Value)
	})
}
