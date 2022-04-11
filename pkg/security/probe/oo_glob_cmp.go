// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"github.com/DataDog/datadog-agent/pkg/security/secl/compiler/eval"
)

var (
	// GlobCmp replaces a pattern matcher with a glob matcher for *file.path fields.
	GlobCmp = &eval.OpOverrides{
		StringEquals: func(a *eval.StringEvaluator, b *eval.StringEvaluator, opts *eval.Opts, state *eval.State) (*eval.BoolEvaluator, error) {
			if a.ValueType == eval.PatternValueType {
				a.ValueType = eval.GlobValueType
			} else if b.ValueType == eval.PatternValueType {
				b.ValueType = eval.GlobValueType
			}

			return eval.StringEquals(a, b, opts, state)
		},
		StringValuesContains: func(a *eval.StringEvaluator, b *eval.StringValuesEvaluator, opts *eval.Opts, state *eval.State) (*eval.BoolEvaluator, error) {
			if a.ValueType == eval.PatternValueType {
				a.ValueType = eval.GlobValueType
			} else {
				var values eval.StringValues
				for _, v := range b.Values.GetFieldValues() {
					if v.Type == eval.PatternValueType {
						v.Type = eval.GlobValueType
					}
					values.AppendFieldValue(v)
				}
				b = &eval.StringValuesEvaluator{
					Values: values,
				}
			}

			return eval.StringValuesContains(a, b, opts, state)
		},
		StringArrayContains: func(a *eval.StringEvaluator, b *eval.StringArrayEvaluator, opts *eval.Opts, state *eval.State) (*eval.BoolEvaluator, error) {
			if a.ValueType == eval.PatternValueType {
				a.ValueType = eval.GlobValueType
			}

			return eval.StringArrayContains(a, b, opts, state)
		},
		StringArrayMatches: func(a *eval.StringArrayEvaluator, b *eval.StringValuesEvaluator, opts *eval.Opts, state *eval.State) (*eval.BoolEvaluator, error) {
			var values eval.StringValues
			for _, v := range b.Values.GetFieldValues() {
				if v.Type == eval.PatternValueType {
					v.Type = eval.GlobValueType
				}
				values.AppendFieldValue(v)
			}
			b = &eval.StringValuesEvaluator{
				Values: values,
			}

			return eval.StringArrayMatches(a, b, opts, state)
		},
	}
)
