package main

import "testing"

func TestCreateAddress(t *testing.T) {
	address := CreateAddressFromSeeds(
		"abandon ability able about above absent absorb abstract absurd abuse access accident")
	print(address)
}
