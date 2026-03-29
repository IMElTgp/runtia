package collect

import (
	"github.com/IMElTgp/container-runtime-analysis/internal/target"
)

type NameSpace struct {
	Threads  map[int]*target.Thread
	Type     string
	Dev, Ino uint64
}
