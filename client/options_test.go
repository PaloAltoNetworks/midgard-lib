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
}
