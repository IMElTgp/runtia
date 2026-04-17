package model

type Signal struct {
	// Signal combines Finding
	Finding
	// Primitive or covered
	// for composited signals, Covered=true
	Covered bool
}
