package schnorr

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func Keygen(bits int) (p, g, y, x *big.Int) {
	p, _ = rand.Prime(rand.Reader, bits)
	g = randomRange(big.NewInt(2), new(big.Int).Sub(p, big.NewInt(1)))
	x = randomRange(big.NewInt(2), new(big.Int).Sub(p, big.NewInt(2)))
	y = new(big.Int).Exp(g, x, p)
	return
}

func ProverCommitment(p, g *big.Int) (t, r *big.Int) {
	r = randomRange(big.NewInt(2), new(big.Int).Sub(p, big.NewInt(2)))
	t = new(big.Int).Exp(g, r, p)
	return
}

func VerifierChallenge(p *big.Int) *big.Int {
	return randomRange(big.NewInt(1), new(big.Int).Sub(p, big.NewInt(1)))
}

func ProverResponse(r, c, x, p *big.Int) *big.Int {
	xc := new(big.Int).Mul(c, x)
	s := new(big.Int).Add(r, xc)
	return s.Mod(s, new(big.Int).Sub(p, big.NewInt(1)))
}

func VerifierCheck(p, g, y, t, c, s *big.Int) bool {
	gs := new(big.Int).Exp(g, s, p)
	yc := new(big.Int).Exp(y, c, p)
	tc := new(big.Int).Mul(t, yc)
	return gs.Cmp(tc.Mod(tc, p)) == 0
}

func schnorrProtocol(bits int) {
	p, g, y, x := Keygen(bits)
	t, r := ProverCommitment(p, g)
	c := VerifierChallenge(p)
	s := ProverResponse(r, c, x, p)

	if VerifierCheck(p, g, y, t, c, s) {
		fmt.Println("Verification successful")
	} else {
		fmt.Println("Verification failed")
	}
}

func schnorrProtocolPredefined(bits int, predefinedX *big.Int) {
    // Assuming that the predefinedX is legitimate and lies between 2 and p-2
    p, g, y, _ := Keygen(bits)
    x := predefinedX
    y = new(big.Int).Exp(g, x, p)  // Compute y using predefined x
    
    t, r := ProverCommitment(p, g)
    c := VerifierChallenge(p)
    s := ProverResponse(r, c, x, p)

    if VerifierCheck(p, g, y, t, c, s) {
        fmt.Println("Verification successful")
    } else {
        fmt.Println("Verification failed")
    }
}

func randomRange(min, max *big.Int) *big.Int {
	rangeInt := new(big.Int).Sub(max, min)
	n, _ := rand.Int(rand.Reader, rangeInt)
	return n.Add(n, min)
}

func main() {
	schnorrProtocol(256)
}
