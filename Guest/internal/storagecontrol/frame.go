package storagecontrol

import (
	"encoding/binary"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"sync"
)

// Frame storage is charged BEFORE allocation. It is independent of data-plane
// capacity and never waits while holding another lease. Snapshot objects owned by
// Authority and decoder objects are additionally bounded by frame/state limits.
type budget struct {
	mu   sync.Mutex
	used int
}

func (b *budget) take(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || n > MaxAggregate-b.used {
		return false
	}
	b.used += n
	return true
}
func (b *budget) release(n int) { b.mu.Lock(); b.used -= n; b.mu.Unlock() }
func readFrame(r io.Reader, dst any, max int, b *budget) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(h[:]))
	if n == 0 || n > max {
		return ErrLimit
	}
	if !b.take(n) {
		return ErrLimit
	}
	defer b.release(n)
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		// EOF is clean only before a header. A declared body that never
		// arrives is a truncated protocol frame, not service unavailability.
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return strictDecode(body, dst)
}
func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// A fixed-capacity response avoids json.Encoder's unbounded full-value staging
// buffer. Recursive encoding handles only our closed structs/maps/scalars.
type boundedJSON struct {
	data []byte
	err  error
}

func (w *boundedJSON) put(p []byte) {
	if w.err != nil {
		return
	}
	if len(p) > cap(w.data)-len(w.data) {
		w.err = ErrLimit
		return
	}
	w.data = append(w.data, p...)
}
func (w *boundedJSON) value(v reflect.Value) {
	if w.err != nil {
		return
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			w.put([]byte("null"))
			return
		}
		w.value(v.Elem())
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		w.put([]byte("{"))
		first := true
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if len(tag) > 1 && tag[1] == "omitempty" && v.Field(i).IsZero() {
				continue
			}
			if !first {
				w.put([]byte(","))
			}
			first = false
			name, _ := json.Marshal(tag[0])
			w.put(name)
			w.put([]byte(":"))
			w.value(v.Field(i))
		}
		w.put([]byte("}"))
	case reflect.Map:
		w.put([]byte("{"))
		it := v.MapRange()
		first := true
		for it.Next() {
			if !first {
				w.put([]byte(","))
			}
			first = false
			w.value(it.Key())
			w.put([]byte(":"))
			w.value(it.Value())
			if w.err != nil {
				return
			}
		}
		w.put([]byte("}"))
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			p, err := json.Marshal(v.Interface())
			if err != nil {
				w.err = ErrProtocol
			}
			w.put(p)
			return
		}
		w.put([]byte("["))
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				w.put([]byte(","))
			}
			w.value(v.Index(i))
			if w.err != nil {
				return
			}
		}
		w.put([]byte("]"))
	default:
		p, err := json.Marshal(v.Interface())
		if err != nil {
			w.err = ErrProtocol
		}
		w.put(p)
	}
}
func writeFrame(w io.Writer, v any, max int, b *budget) error {
	if !b.take(max) {
		return ErrLimit
	}
	defer b.release(max)
	out := boundedJSON{data: make([]byte, 0, max)}
	out.value(reflect.ValueOf(v))
	if out.err != nil {
		return out.err
	}
	var h [4]byte
	binary.BigEndian.PutUint32(h[:], uint32(len(out.data)))
	if err := writeFull(w, h[:]); err != nil {
		return err
	}
	return writeFull(w, out.data)
}
