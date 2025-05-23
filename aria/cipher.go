package aria

import "fmt"

type Aria struct {
	size    int
	encKeys []uint32
	decKeys []uint32
}

func NewAria(key []byte) (*Aria, error) {
	k := len(key)

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("ARIA: invalid key size")
	}

	c := Aria{
		size:    k,
		encKeys: make([]uint32, k+36),
		decKeys: make([]uint32, k+36),
	}

	if err := c.expandKey(key); err != nil {
		return nil, fmt.Errorf("aria: key expansion failed: %w", err)
	}

	return &c, nil
}

func (c *Aria) rounds() int {
	return c.size/4 + 8
}
