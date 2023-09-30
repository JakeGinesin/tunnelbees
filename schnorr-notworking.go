package schnorrbad

import (
	"crypto/rand"
	"math/big"
)

var pp, qq, gg *big.Int

func Setup(p, q, g *big.Int) {
	pp = p
	qq = q
	gg = g
}

func ComputeV(s *big.Int) *big.Int {
	// v = g^(-s) mod p
	negS := new(big.Int).Neg(s)
	negS.Mod(negS, qq)

	v := new(big.Int).Exp(gg, negS, pp)
	return v
}

func ProverStep1(s *big.Int) (*big.Int, *big.Int) {
	// r is a random number from Zq
	r, _ := rand.Int(rand.Reader, qq)

	// t = g^r mod p
	t := new(big.Int).Exp(gg, r, pp)

	return r, t
}

func VerifierChallenge() *big.Int {
	// Random challenge c from Zq
	c, _ := rand.Int(rand.Reader, qq)
	return c
}

func ProverStep2(r, s, c *big.Int) *big.Int {
	// u = r + c * s mod q
	temp := new(big.Int).Mul(c, s)
	u := new(big.Int).Add(r, temp)
	u.Mod(u, qq)

	return u
}

func VerifierCheck(t, v, c, u *big.Int) bool {
	// gu ≡ t * v^c mod p
	left := new(big.Int).Exp(gg, u, pp)

	right1 := new(big.Int).Exp(v, c, pp)
	right := new(big.Int).Mul(t, right1)
	right.Mod(right, pp)

	return left.Cmp(right) == 0
}
