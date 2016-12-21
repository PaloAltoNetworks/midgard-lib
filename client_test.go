package midgardclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

func TestClient_NewClient(t *testing.T) {

	Convey("Given I create a new Client with a valid URL", t, func() {

		cl := NewClient("http://com.com")

		Convey("Then client should be correctly initialized", func() {
			So(cl, ShouldNotBeNil)
		})

		Convey("Then client url should be set", func() {
			So(cl.url, ShouldEqual, "http://com.com")
		})
	})

	Convey("Given I create a new Client with a missing URL", t, func() {

		Convey("Then it should panic", func() {
			So(func() { NewClient("") }, ShouldPanic)
		})
	})
}

func TestClient_Authentify(t *testing.T) {

	Convey("Given I have a Client and some valid http header", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "claims": {
                   "aud": "aporeto.com",
                   "data": {
                       "commonName": "superadmin",
                       "organization": "aporeto.com",
                       "organizationalUnit": "SuperAdmin"
                   },
                   "exp": 1475083201,
                   "iat": 1474996801,
                   "iss": "midgard.aporeto.com",
                   "realm": "certificate",
                   "sub": "10237207344299343489"
               }
            }`)
		}))
		defer ts.Close()

		cl := NewClient(ts.URL)

		Convey("When I call Authentify", func() {

			n, err := cl.Authentify("thetoken")

			Convey("Then I should get valid normalization", func() {
				So(n, ShouldContain, "auth:subject=10237207344299343489")
			})

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})
		})
	})

	Convey("Given I have a Client and some valid http header but Midgard doesn't respond", t, func() {

		cl := NewClient("http://sdfjdfjkshfjkhdskfhsdjkfhsdkfhsdkjfhsdjjshsjkgdsg.gsdjghdjgfdfjghdhfgdfjhg.dfgj")

		Convey("When I call Authentify", func() {

			n, err := cl.Authentify("thetoken")

			Convey("Then normalization should be nil", func() {
				So(n, ShouldBeNil)
			})

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a Client and some valid http header but Midgard doesn't approve", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			fmt.Fprintln(w, `{
                "claims": null
            }`)
		}))
		defer ts.Close()

		cl := NewClient(ts.URL)

		Convey("When I call Authentify", func() {

			n, err := cl.Authentify("thetoken")

			Convey("Then normalization should be nil", func() {
				So(n, ShouldBeNil)
			})

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})

	Convey("Given I have a Client and some valid http header but Midgard return garbage json", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "claims
            }`)
		}))
		defer ts.Close()

		cl := NewClient(ts.URL)

		Convey("When I call Authentify", func() {

			n, err := cl.Authentify("thetoken")

			Convey("Then normalization should be nil", func() {
				So(n, ShouldBeNil)
			})

			Convey("Then err should be not nil", func() {
				So(err, ShouldNotBeNil)
			})
		})
	})
}

func TestClient_IssueFromGoogle(t *testing.T) {

	Convey("Given I have a client and a fake working server", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "data": "",
                "realm": "google",
                "token": "yeay!"
            }`)
		}))

		cl := NewClient(ts.URL)

		Convey("When I call IssueFromGoogle with a valid token", func() {

			jwt, err := cl.IssueFromGoogle("eyJhbGciOiJSUzI1NiIsImtpZCI6IjQwZDg0OTU5YjY1ZGZmM2QwNTJkYjI1YmZhZTRmZTAyMmI4MzVjYTUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Ik91S0JGYmpjZjdYWjNkVjV0ZnZmLXciLCJhdWQiOiIzMzA5OTY3Nzc4NjUtaWo4cG1la2dldTVmMGVqb2hqMW9vMzNqaXAwc2xza2kuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTYzNjU0ODU0MTQ0NDgyODcwODgiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMzMwOTk2Nzc3ODY1LWlqOHBtZWtnZXU1ZjBlam9oajFvbzMzamlwMHNsc2tpLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJhbnRvaW5lLm1lcmNhZGFsQGdtYWlsLmNvbSIsImlhdCI6MTQ3NDk5ODQwMCwiZXhwIjoxNDc1MDAyMDAwLCJuYW1lIjoiQW50b2luZSBNZXJjYWRhbCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLWFLcU1yRERYTk1BL0FBQUFBQUFBQUFJL0FBQUFBQUFBRDcwL29QQU53NDE1U0xRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbnRvaW5lIiwiZmFtaWx5X25hbWUiOiJNZXJjYWRhbCIsImxvY2FsZSI6ImVuIn0.LVh_3xr2qRdSQ-dfYHs9Zp6fkZUeBneURjKlTKujw_9FjY96BuoUxiPlMndAHZd-JEsQcJ01GueB3zt6xyYOkPeRbQ7tFGE8NhwbR5TYadR7FuEsNmCLc8oTnHrP_w7YVAdDhjdSFJd-y7XTIQxFuApjDQM0rBFknUoOC69n_VKG53wt7np0L2ZdGQgEw5a9s6wgBvdNZ9_lKPJZjapG_K8D7YsICrAdZ4vO8FR4hyqwBoCm8uUP6RaBzQWjt6D6DpWBsoLeMGDTONvK3-PZdfcERXe2qTelq29FfzS1eMGywIXkgo-DkWaTJH38wMyJ3x2Egq6A-TP7_asqKC7qew")

			Convey("Then err should be nil", func() {
				So(err, ShouldBeNil)
			})

			Convey("Then jwt be correct", func() {
				So(jwt, ShouldEqual, "yeay!")
			})
		})
	})

	Convey("Given I have a client with an invalid URL", t, func() {

		cl := NewClient("http:/ssaffsdf")

		jwt, err := cl.IssueFromGoogle("eyJhbGciOiJSUzI1NiIsImtpZCI6IjQwZDg0OTU5YjY1ZGZmM2QwNTJkYjI1YmZhZTRmZTAyMmI4MzVjYTUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Ik91S0JGYmpjZjdYWjNkVjV0ZnZmLXciLCJhdWQiOiIzMzA5OTY3Nzc4NjUtaWo4cG1la2dldTVmMGVqb2hqMW9vMzNqaXAwc2xza2kuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTYzNjU0ODU0MTQ0NDgyODcwODgiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMzMwOTk2Nzc3ODY1LWlqOHBtZWtnZXU1ZjBlam9oajFvbzMzamlwMHNsc2tpLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJhbnRvaW5lLm1lcmNhZGFsQGdtYWlsLmNvbSIsImlhdCI6MTQ3NDk5ODQwMCwiZXhwIjoxNDc1MDAyMDAwLCJuYW1lIjoiQW50b2luZSBNZXJjYWRhbCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLWFLcU1yRERYTk1BL0FBQUFBQUFBQUFJL0FBQUFBQUFBRDcwL29QQU53NDE1U0xRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbnRvaW5lIiwiZmFtaWx5X25hbWUiOiJNZXJjYWRhbCIsImxvY2FsZSI6ImVuIn0.LVh_3xr2qRdSQ-dfYHs9Zp6fkZUeBneURjKlTKujw_9FjY96BuoUxiPlMndAHZd-JEsQcJ01GueB3zt6xyYOkPeRbQ7tFGE8NhwbR5TYadR7FuEsNmCLc8oTnHrP_w7YVAdDhjdSFJd-y7XTIQxFuApjDQM0rBFknUoOC69n_VKG53wt7np0L2ZdGQgEw5a9s6wgBvdNZ9_lKPJZjapG_K8D7YsICrAdZ4vO8FR4hyqwBoCm8uUP6RaBzQWjt6D6DpWBsoLeMGDTONvK3-PZdfcERXe2qTelq29FfzS1eMGywIXkgo-DkWaTJH38wMyJ3x2Egq6A-TP7_asqKC7qew")

		Convey("Then err should not be nil", func() {
			So(err, ShouldNotBeNil)
		})

		Convey("Then jwt be empty", func() {
			So(jwt, ShouldBeEmpty)
		})
	})

	Convey("Given I have a client and a working fake server ", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(403)
			fmt.Fprintln(w, `{
                "data": "",
                "realm": "google",
                "token": "yeay!"
            }`)
		}))

		cl := NewClient(ts.URL)

		Convey("When I call IssueFromGoogle with an invalid token", func() {

			jwt, err := cl.IssueFromGoogle("eyJhbGciOiJSUzI1NiIsImtpZCI6IjQwZDg0OTU5YjY1ZGZmM2QwNTJkYjI1YmZhZTRmZTAyMmI4MzVjYTUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Ik91S0JGYmpjZjdYWjNkVjV0ZnZmLXciLCJhdWQiOiIzMzA5OTY3Nzc4NjUtaWo4cG1la2dldTVmMGVqb2hqMW9vMzNqaXAwc2xza2kuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTYzNjU0ODU0MTQ0NDgyODcwODgiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMzMwOTk2Nzc3ODY1LWlqOHBtZWtnZXU1ZjBlam9oajFvbzMzamlwMHNsc2tpLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJhbnRvaW5lLm1lcmNhZGFsQGdtYWlsLmNvbSIsImlhdCI6MTQ3NDk5ODQwMCwiZXhwIjoxNDc1MDAyMDAwLCJuYW1lIjoiQW50b2luZSBNZXJjYWRhbCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLWFLcU1yRERYTk1BL0FBQUFBQUFBQUFJL0FBQUFBQUFBRDcwL29QQU53NDE1U0xRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbnRvaW5lIiwiZmFtaWx5X25hbWUiOiJNZXJjYWRhbCIsImxvY2FsZSI6ImVuIn0.LVh_3xr2qRdSQ-dfYHs9Zp6fkZUeBneURjKlTKujw_9FjY96BuoUxiPlMndAHZd-JEsQcJ01GueB3zt6xyYOkPeRbQ7tFGE8NhwbR5TYadR7FuEsNmCLc8oTnHrP_w7YVAdDhjdSFJd-y7XTIQxFuApjDQM0rBFknUoOC69n_VKG53wt7np0L2ZdGQgEw5a9s6wgBvdNZ9_lKPJZjapG_K8D7YsICrAdZ4vO8FR4hyqwBoCm8uUP6RaBzQWjt6D6DpWBsoLeMGDTONvK3-PZdfcERXe2qTelq29FfzS1eMGywIXkgo-DkWaTJH38wMyJ3x2Egq6A-TP7_asqKC7qew")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then jwt be empty", func() {
				So(jwt, ShouldBeEmpty)
			})
		})
	})

	Convey("Given I have a client and a fake server that returns garbage", t, func() {

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, `{
                "data": "
            }`)
		}))

		cl := NewClient(ts.URL)

		Convey("When I call IssueFromGoogle with a valid token", func() {

			jwt, err := cl.IssueFromGoogle("eyJhbGciOiJSUzI1NiIsImtpZCI6IjQwZDg0OTU5YjY1ZGZmM2QwNTJkYjI1YmZhZTRmZTAyMmI4MzVjYTUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6Ik91S0JGYmpjZjdYWjNkVjV0ZnZmLXciLCJhdWQiOiIzMzA5OTY3Nzc4NjUtaWo4cG1la2dldTVmMGVqb2hqMW9vMzNqaXAwc2xza2kuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTYzNjU0ODU0MTQ0NDgyODcwODgiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiMzMwOTk2Nzc3ODY1LWlqOHBtZWtnZXU1ZjBlam9oajFvbzMzamlwMHNsc2tpLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJhbnRvaW5lLm1lcmNhZGFsQGdtYWlsLmNvbSIsImlhdCI6MTQ3NDk5ODQwMCwiZXhwIjoxNDc1MDAyMDAwLCJuYW1lIjoiQW50b2luZSBNZXJjYWRhbCIsInBpY3R1cmUiOiJodHRwczovL2xoMy5nb29nbGV1c2VyY29udGVudC5jb20vLWFLcU1yRERYTk1BL0FBQUFBQUFBQUFJL0FBQUFBQUFBRDcwL29QQU53NDE1U0xRL3M5Ni1jL3Bob3RvLmpwZyIsImdpdmVuX25hbWUiOiJBbnRvaW5lIiwiZmFtaWx5X25hbWUiOiJNZXJjYWRhbCIsImxvY2FsZSI6ImVuIn0.LVh_3xr2qRdSQ-dfYHs9Zp6fkZUeBneURjKlTKujw_9FjY96BuoUxiPlMndAHZd-JEsQcJ01GueB3zt6xyYOkPeRbQ7tFGE8NhwbR5TYadR7FuEsNmCLc8oTnHrP_w7YVAdDhjdSFJd-y7XTIQxFuApjDQM0rBFknUoOC69n_VKG53wt7np0L2ZdGQgEw5a9s6wgBvdNZ9_lKPJZjapG_K8D7YsICrAdZ4vO8FR4hyqwBoCm8uUP6RaBzQWjt6D6DpWBsoLeMGDTONvK3-PZdfcERXe2qTelq29FfzS1eMGywIXkgo-DkWaTJH38wMyJ3x2Egq6A-TP7_asqKC7qew")

			Convey("Then err should not be nil", func() {
				So(err, ShouldNotBeNil)
			})

			Convey("Then jwt be empty", func() {
				So(jwt, ShouldBeEmpty)
			})
		})
	})
}
