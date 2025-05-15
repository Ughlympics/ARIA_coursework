package aria

import "fmt"

type Aria struct {
	size    int
	encKeys []uint32
	decKeys []uint32
}

func NewAria(key []byte) (*Aria, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("ARIA: invalid key size")
	}
	c := &Aria{}
	err := c.expandKey(key)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Aria) rounds() int {
	return c.size/4 + 8
}
