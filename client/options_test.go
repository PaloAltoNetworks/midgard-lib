// Copyright 2019 Aporeto Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package midgardclient

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestBahamut_Options(t *testing.T) {

	c := issueOpts{}

	Convey("Calling OptQuota should work", t, func() {
		OptQuota(12)(&c)
		So(c.quota, ShouldEqual, 12)
	})

	Convey("Calling OptQuota with 0 should work", t, func() {
		OptQuota(0)(&c)
		So(c.quota, ShouldEqual, 0)
	})

	Convey("Calling OptQuota with a negative value should panic", t, func() {
		So(func() { OptQuota(-1)(&c) }, ShouldPanicWith, "quota must be a positive number")
	})

	Convey("Calling OptOpaque should work", t, func() {
		OptOpaque(map[string]string{"a": "b"})(&c)
		So(c.opaque, ShouldResemble, map[string]string{"a": "b"})
	})

	Convey("Calling OptAudience should work", t, func() {
		OptAudience("audience")(&c)
		So(c.audience, ShouldResemble, "audience")
	})

	Convey("Calling OptLimitAuthz should work", t, func() {
		OptLimitAuthz("/ns", "@auth:role=toto", "test,get,post,put")(&c)
		So(c.authorizedIdentities, ShouldResemble, []string{"@auth:role=toto", "test,get,post,put"})
		So(c.authorizedNamespace, ShouldEqual, "/ns")
	})
}
