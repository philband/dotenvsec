package cli

import "testing"

func TestNormalizeExecArguments(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"separator", []string{"--", "tofu", "plan"}, "tofu"},
		{"without separator", []string{"tofu", "plan"}, "tofu"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual, err := normalizeExecArguments(test.args)
			if err != nil {
				t.Fatal(err)
			}
			if actual[0] != test.want {
				t.Fatalf("first argument = %q, want %q", actual[0], test.want)
			}
		})
	}
}

func TestNormalizeExecArgumentsRejectsMissingCommand(t *testing.T) {
	for _, args := range [][]string{nil, {"--"}} {
		if _, err := normalizeExecArguments(args); err == nil {
			t.Fatalf("expected error for %#v", args)
		}
	}
}
