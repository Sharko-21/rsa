package rsa

import (
	crpytroRand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
	"time"
)

type key struct {
	A *big.Int
	B *big.Int
}

type RSAKeys struct {
	PublicKey  key
	privateKey key
}

type RSAID int64

var keys = make(map[RSAID]*RSAKeys, 32)
var rsaId RSAID = 0

func GenerateKeys(bits int) *RSAKeys {
	var P, Q, N, exponent *big.Int
	P, err := crpytroRand.Prime(crpytroRand.Reader, bits)
	if err != nil {
		return &RSAKeys{}
	}
	Q, err = crpytroRand.Prime(crpytroRand.Reader, bits)
	if err != nil {
		return &RSAKeys{}
	}

	N1 := new(big.Int).Sub(P, big.NewInt(1))
	N2 := new(big.Int).Sub(Q, big.NewInt(1))
	N = new(big.Int).Mul(N1, N2)
	module := new(big.Int).Mul(P, Q)
	if N.BitLen() > 64 {
		exponent = big.NewInt(int64(rand.Intn(int(math.MaxInt64))))
	} else {
		exponent = big.NewInt(int64(rand.Intn(int(N.Int64()))))
	}
	for !isCoprimeBig(N, exponent) {
		time.Sleep(100 * time.Millisecond)
		if N.BitLen() > 64 {
			exponent = big.NewInt(int64(rand.Intn(int(math.MaxInt64))))
		} else {
			exponent = big.NewInt(int64(rand.Intn(int(N.Int64()))))
		}
	}
	secretExponent := evklidBig(N, exponent)
	if secretExponent.Cmp(big.NewInt(0)) == -1 {
		secretExponent = new(big.Int).Add(secretExponent, N)
	}

	keys[rsaId] = &RSAKeys{PublicKey: key{A: exponent, B: module}, privateKey: key{A: secretExponent, B: module}}
	return keys[rsaId]
}

func Encrypt(message *big.Int, keys *RSAKeys) *big.Int {
	encryptedMessage := new(big.Int).Exp(message, keys.PublicKey.A, nil)
	encryptedMessage = encryptedMessage.Mod(encryptedMessage, keys.PublicKey.B)
	return encryptedMessage
}

func Decrypt(message *big.Int, keys *RSAKeys) *big.Int {
	decryptedMessage := new(big.Int).Exp(message, keys.privateKey.A, nil)
	decryptedMessage = decryptedMessage.Mod(decryptedMessage, keys.privateKey.B)
	return decryptedMessage
}

func isCoprimeBig(a, b *big.Int) bool {
	if gcdBig(a, b).Cmp(big.NewInt(1)) == 0 {
		return true
	}
	return false
}

func gcdBig(a, b *big.Int) *big.Int {
	if a.Cmp(big.NewInt(0)) == 0 || b.Cmp(big.NewInt(0)) == 0 {
		return big.NewInt(0)
	}

	if a.Cmp(b) == 0 {
		return a
	}

	if a.Cmp(b) == 1 {
		return gcdBig(new(big.Int).Sub(a, b), b)
	}
	return gcdBig(a, new(big.Int).Sub(b, a))
}

func evklidBig(a, b *big.Int) *big.Int {
	var q, r, x1, x2, y1, y2 *big.Int
	var mas = []*big.Int{big.NewInt(0), big.NewInt(0)}
	if b.Cmp(big.NewInt(0)) == 0 {
		mas[0] = big.NewInt(1)
		mas[1] = big.NewInt(0)
	}

	x2 = big.NewInt(1)
	x1 = big.NewInt(0)
	y2 = big.NewInt(0)
	y1 = big.NewInt(1)

	for b.Cmp(big.NewInt(0)) == 1 {
		q = new(big.Int).Div(a, b)
		r = new(big.Int).Sub(a, new(big.Int).Mul(q, b))
		mas[0] = new(big.Int).Sub(x2, new(big.Int).Mul(q, x1))
		mas[1] = new(big.Int).Sub(y2, new(big.Int).Mul(q, y1))
		a = new(big.Int).Mul(b, big.NewInt(1))
		b = new(big.Int).Mul(r, big.NewInt(1))
		x2 = new(big.Int).Mul(x1, big.NewInt(1))
		x1 = new(big.Int).Mul(mas[0], big.NewInt(1))
		y2 = new(big.Int).Mul(y1, big.NewInt(1))
		y1 = new(big.Int).Mul(mas[1], big.NewInt(1))
	}

	mas[0] = x2
	mas[1] = y2
	return y2
}
