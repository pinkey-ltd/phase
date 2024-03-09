package otp

import "testing"

func TestHotp_GenerateCode(t *testing.T) {
	type fields struct {
		config *Config
	}
	type args struct {
		counter uint64
	}
	tests := []struct {
		name         string
		fields       fields
		args         args
		wantPasscode string
		wantErr      bool
	}{
		{
			name: "default",
			fields: fields{&Config{
				Period:     30,
				SecretSize: 20,
				Secret:     []byte("12345678901234567890"),
				Skew:       0,
				Digits:     DigitsSix,
				Algorithm:  AlgorithmSHA1,
			}},
			args:         args{counter: 0},
			wantPasscode: "755224",
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &Hotp{
				config: tt.fields.config,
			}
			gotPasscode, err := h.GenerateCode(tt.args.counter)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPasscode != tt.wantPasscode {
				t.Errorf("GenerateCode() gotPasscode = %v, want %v", gotPasscode, tt.wantPasscode)
			}
		})
	}
}
