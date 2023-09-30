package main

import (
	"fmt"
	"math/big"
	"tunnelbees/schnorr"
)

func main() {
	// Sample values for p, q, and g

  p, _ := new(big.Int).SetString("47", 10)
  q, _ := new(big.Int).SetString("23", 10)
  g, _ := new(big.Int).SetString("5", 10)

	schnorr.Setup(p, q, g)

	// Secret s
	s := big.NewInt(6)
	v := schnorr.ComputeV(s)

	// Prover's step 1
	r, t := schnorr.ProverStep1(s)

	// Verifier sends challenge
	c := schnorr.VerifierChallenge()

	// Prover's step 2
	u := schnorr.ProverStep2(r, s, c)

	// Verifier checks the equation
	result := schnorr.VerifierCheck(t, v, c, u)
	fmt.Println("Verification result:", result) // Expected: true
}
