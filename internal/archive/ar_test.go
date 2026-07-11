package archive

import (
	"bytes"
	"testing"
)

// buildAr constructs a minimal ar archive with the given named members.
func buildAr(t *testing.T, members map[string][]byte, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(arMagic)
	for _, name := range order {
		data := members[name]
		header := make([]byte, 60)
		copy(header[0:], padRight(name+"/", 16))
		copy(header[16:], padRight("0", 12))     // mtime
		copy(header[28:], padRight("0", 6))      // uid
		copy(header[34:], padRight("0", 6))      // gid
		copy(header[40:], padRight("100644", 8)) // mode
		copy(header[48:], padRight(itoa(len(data)), 10))
		header[58] = '`'
		header[59] = '\n'
		buf.Write(header)
		buf.Write(data)
		if len(data)%2 == 1 {
			buf.WriteByte('\n')
		}
	}
	return buf.Bytes()
}

func padRight(s string, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = ' '
	}
	copy(out, s)
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

func TestParseArRoundTrip(t *testing.T) {
	members := map[string][]byte{
		"debian-binary":  []byte("2.0\n"),
		"control.tar.gz": bytes.Repeat([]byte{0xAB}, 13), // odd length exercises padding
		"data.tar.xz":    []byte("fake-xz-data"),
	}
	order := []string{"debian-binary", "control.tar.gz", "data.tar.xz"}
	data := buildAr(t, members, order)

	entries, err := ParseAr(data)
	if err != nil {
		t.Fatalf("ParseAr: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	for i, name := range order {
		if entries[i].Name != name {
			t.Errorf("entry %d: got name %q, want %q", i, entries[i].Name, name)
		}
		if !bytes.Equal(entries[i].Data, members[name]) {
			t.Errorf("entry %q: data mismatch", name)
		}
	}

	dataMember, ok := FindMember(entries, "data.tar")
	if !ok || dataMember.Name != "data.tar.xz" {
		t.Fatalf("FindMember(data.tar) = %v, %v", dataMember, ok)
	}
}

func TestParseArBadMagic(t *testing.T) {
	if _, err := ParseAr([]byte("not an ar file")); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

func TestParseArOversizedMember(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString(arMagic)
	header := make([]byte, 60)
	copy(header[0:], padRight("evil/", 16))
	copy(header[48:], padRight("99999999999", 10)) // > 1GiB guard
	header[58], header[59] = '`', '\n'
	buf.Write(header)

	if _, err := ParseAr(buf.Bytes()); err == nil {
		t.Fatal("expected oversized member to be rejected")
	}
}
