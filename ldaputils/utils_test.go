package ldaputils

import (
	"reflect"
	"testing"
)

func Test_findLDAPKey(t *testing.T) {
	type args struct {
		k        string
		metadata map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Test non-existent key",
			args: args{
				k:        "k",
				metadata: map[string]interface{}{},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Test key with empty value",
			args: args{
				k: "k",
				metadata: map[string]interface{}{
					"k": "",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Test key with some value",
			args: args{
				k: "k",
				metadata: map[string]interface{}{
					"k": "some-value",
				},
			},
			want:    "some-value",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findLDAPKey(tt.args.k, tt.args.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("findLDAPKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("findLDAPKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findLDAPKeyMap(t *testing.T) {
	type args struct {
		k        string
		metadata map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		wantM   map[string]interface{}
		wantErr bool
	}{
		{
			name: "Test non-existent key",
			args: args{
				k:        "k",
				metadata: map[string]interface{}{},
			},
			wantM:   nil,
			wantErr: true,
		},
		{
			name: "Test key with non-list",
			args: args{
				k: "k",
				metadata: map[string]interface{}{
					"k": 5,
				},
			},
			wantM:   nil,
			wantErr: true,
		},
		{
			name: "Test key with empty list",
			args: args{
				k: "k",
				metadata: map[string]interface{}{
					"k": []string{},
				},
			},
			wantM:   map[string]interface{}{},
			wantErr: false,
		},
		{
			name: "Test key with list",
			args: args{
				k: "k",
				metadata: map[string]interface{}{
					"k": []string{"some-key"},
				},
			},
			wantM: map[string]interface{}{
				"some-key": nil,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotM, err := findLDAPKeyMap(tt.args.k, tt.args.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("findLDAPKeyMap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotM, tt.wantM) {
				t.Errorf("findLDAPKeyMap() = %v, want %v", gotM, tt.wantM)
			}
		})
	}
}
