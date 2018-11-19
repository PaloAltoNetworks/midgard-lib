package tokenmanager

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
)

func TestTokenManager_Issue(t *testing.T) {

	Convey("Given I a periodic token manager without issue func", t, func() {

		Convey("Then it should panic", func() {
			So(func() { NewPeriodicTokenManager(10*time.Second, nil) }, ShouldPanicWith, "issuerFunc cannot be nil")
		})
	})

	Convey("Given I have TokenIssuerFunc that works and a token manager", t, func() {

		tf := func(ctx context.Context, v time.Duration) (string, error) {
			return "token!", nil
		}

		tm := NewPeriodicTokenManager(10*time.Second, tf)

		Convey("When I call Issue", func() {
			t, err := tm.Issue(context.Background())

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then I should get a token", func() {
				So(t, ShouldEqual, "token!")
			})
		})
	})
}

func TestTokenManager_Run(t *testing.T) {

	tickDuration = 1 * time.Millisecond

	Convey("Given I have TokenIssuerFunc that works and a token manager", t, func() {

		var called int32
		tf := func(ctx context.Context, v time.Duration) (string, error) {
			atomic.AddInt32(&called, 1)
			return "token!", nil
		}

		tm := NewPeriodicTokenManager(2*time.Millisecond, tf)

		Convey("When I call Run and wait for a few", func() {

			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			tokenCh := make(chan string)
			go tm.Run(ctx, tokenCh)

			var c int
			var lastToken string
		L:
			for {
				select {
				case lastToken = <-tokenCh:
					c++
					if c == 4 {
						break L
					}
				case <-ctx.Done():
					panic("timeout exceeded")
				}
			}

			Convey("Then I should have received 4 tokens", func() {
				So(c, ShouldEqual, 4)
			})

			Convey("Then the renew should have been called 4 time", func() {
				So(atomic.LoadInt32(&called), ShouldEqual, 4)
			})

			Convey("Then the token should be in the chan", func() {
				So(lastToken, ShouldEqual, "token!")
			})
		})
	})

	Convey("Given I have TokenIssuerFunc that fails and a token manager", t, func() {

		var called int32
		tf := func(ctx context.Context, v time.Duration) (string, error) {
			atomic.AddInt32(&called, 1)
			return "", fmt.Errorf("bim")
		}

		tm := NewPeriodicTokenManager(2*time.Millisecond, tf)

		Convey("When I call Run and wait for a few", func() {

			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

			tokenCh := make(chan string)
			go tm.Run(ctx, tokenCh)

		L:
			for {
				select {
				case <-tokenCh:
					panic("received a token")
				case <-ctx.Done():
					break L
				}
			}

			cancel()

			Convey("Then the renew should have been called several times", func() {
				So(atomic.LoadInt32(&called), ShouldBeGreaterThan, 0)
			})
		})
	})
}
