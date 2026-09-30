package devicename

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name, input, want, encoding string
	}{
		{name: "plain utf8", input: "刘璐的 Mac mini", want: "刘璐的 Mac mini"},
		{name: "escaped utf8", input: `Mac-\xe5\xae\xa2\xe6\x88\xb7\xe7\xab\xaf`, want: "Mac-客户端", encoding: "utf-8-escape"},
		{name: "escaped gb18030", input: `ld\xb5\xc4\xb5\xe7\xc4\xd4`, want: "ld的电脑", encoding: "gb18030-escape"},
		{name: "invalid escape", input: `host\xzz`, want: ""},
		{name: "control", input: "host\nname", want: ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, encoding := Normalize(test.input)
			if got != test.want || encoding != test.encoding {
				t.Fatalf("Normalize(%q)=(%q,%q), want (%q,%q)", test.input, got, encoding, test.want, test.encoding)
			}
		})
	}
}
