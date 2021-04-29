// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcec

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	// ErrInvalidMAC occurs when Message Authentication Check (MAC) fails
	// during decryption. This happens because of either invalid private key or
	// corrupt ciphertext.
	ErrInvalidMAC = errors.New("invalid mac hash")

	// errInputTooShort occurs when the input ciphertext to the Decrypt
	// function is less than 134 bytes long.
	errInputTooShort = errors.New("ciphertext too short")

	// errUnsupportedCurve occurs when the first two bytes of the encrypted
	// text aren't 0x02CA (= 712 = secp256k1, from OpenSSL).
	errUnsupportedCurve = errors.New("unsupported curve")

	errInvalidXLength = errors.New("invalid X length, must be 32")
	errInvalidYLength = errors.New("invalid Y length, must be 32")
	errInvalidPadding = errors.New("invalid PKCS#7 padding")

	// 0x02CA = 714
	ciphCurveBytes = [2]byte{0x02, 0xCA}
	// 0x20 = 32
	ciphCoordLength = [2]byte{0x00, 0x20}
)

// GenerateSharedSecret generates a shared secret based on a private key and a
// public key using Diffie-Hellman key exchange (ECDH) (RFC 4753).
// RFC5903 Section 9 states we should only return x.
func GenerateSharedSecret(privkey *PrivateKey, pubkey *PublicKey) []byte {
	x, _ := pubkey.Curve.ScalarMult(pubkey.X, pubkey.Y, privkey.D.Bytes())
	return x.Bytes()
}

// Encrypt encrypts data for the target public key using AES-256-CBC. It also
// generates a private key (the pubkey of which is also in the output). The only
// supported curve is secp256k1. The `structure' that it encodes everything into
// is:
//
//	struct {
//		// Initialization Vector used for AES-256-CBC
//		IV [16]byte
//		// Public Key: curve(2) + len_of_pubkeyX(2) + pubkeyX +
//		// len_of_pubkeyY(2) + pubkeyY (curve = 714)
//		PublicKey [70]byte
//		// Cipher text
//		Data []byte
//		// HMAC-SHA-256 Message Authentication Code
//		HMAC [32]byte
//	}
//
// The primary aim is to ensure byte compatibility with Pyelliptic.  Also, refer
// to section 5.8.1 of ANSI X9.63 for rationale on this format.

/*
var mlen int = 32
var T1x = make([]*big.Int, 65537)
var T1y = make([]*big.Int, 65537)
var T2x = make([]*big.Int, 65536)
var T2y = make([]*big.Int, 65536)
*/

var T2x = make([]*fieldVal, 8192)
var T2y = make([]*fieldVal, 8192)
var ZTree = make([]*fieldVal, 16384)
var ZinvTree = make([]*fieldVal, 16384)

var T1 = make(map[[8]byte]int64, 16777216)

// var T1 = make(map[string]int64, 67108864)

//var T1 = offheap.NewStringHashTable(16777216)

func TestInv() {
	a, b, c, d := new(fieldVal), new(fieldVal), new(fieldVal), new(fieldVal)
	ainv, binv, cinv := new(fieldVal), new(fieldVal), new(fieldVal)
	ab, bc, ac := new(fieldVal), new(fieldVal), new(fieldVal)
	var a_inv, b_inv, c_inv fieldVal
	a.SetInt(2)
	a_inv.Set(a)
	a_inv.Inverse()
	b.SetInt(3)
	b_inv.Set(b)
	b_inv.Inverse()
	c.SetInt(4)
	c_inv.Set(c)
	c_inv.Inverse()
	d = d.Mul2(a, b)
	d = d.Mul2(d, c)
	d.Inverse()
	fmt.Println(a_inv.String())
	fmt.Println(b_inv.String())
	fmt.Println(c_inv.String())
	ab = ab.Mul2(a, b)
	bc = bc.Mul2(b, c)
	ac = ac.Mul2(a, c)
	ainv = ainv.Mul2(d, bc)
	binv = binv.Mul2(d, ac)
	cinv = cinv.Mul2(d, ab)
	fmt.Println(ainv.String())
	fmt.Println(binv.String())
	fmt.Println(cinv.String())
}

func BuildTree(zs []*fieldVal) (root *fieldVal) {
	for i := 0; i < 8192; i++ {
		ZTree[i] = zs[i]
	}
	offset := 8192
	for i := 0; i < 16381; i += 2 {
		z := new(fieldVal)
		zmult := z.Mul2(ZTree[i], ZTree[i+1])
		zmult.Normalize()
		ZTree[offset] = zmult
		offset = offset + 1
		if i == 16380 {
			root = zmult
		}
	}
	return root
}

func min(x int, y int) int {
	if x < y {
		return x
	} else {
		return y
	}
}

func GetTreeBranch(index int) [12]int {
	var BranchIndex [12]int
	j := 0
	k := 0
	zsize := 4096
	for ; zsize > 1; zsize = zsize / 2 {
		i := min(index^1, zsize-1) // nindex^1是异或操作，取邻节点
		BranchIndex[k] = j + i
		k = k + 1
		index = index >> 1 // 右移一位，除以二
		j = j + zsize      // 树的上一层级
	}
	return BranchIndex
}

func GetInvTree(rootinv *fieldVal) {
	prevfloorflag := 16382
	prevfloornum := 1
	thisfloorflag := 16382
	treeroot_inv := new(fieldVal)
	treeroot_inv.Set(rootinv)
	ZinvTree[prevfloorflag] = treeroot_inv
	for i := 0; i < 13; i++ {
		thisfloornum := prevfloornum * 2
		thisfloorflag = prevfloorflag - thisfloornum
		for f := 0; f < thisfloornum; f++ {
			thisindex := f + thisfloorflag
			ztreeindex := thisindex ^ 1
			thisindexvalue := new(fieldVal)
			thisindexvalue.Set(ZTree[ztreeindex])
			thisindexvalue.Mul2(thisindexvalue, ZinvTree[prevfloorflag+(f/2)])
			ZinvTree[thisindex] = thisindexvalue
		}
		prevfloorflag = thisfloorflag
		prevfloornum = prevfloornum * 2
	}
}

/*
func GetTreeBranchMult(branchindex [16]int) *fieldVal {
	//branchmult = ZTree[branchindex[0]]
	//fmt.Println(branchmult)
	//fmt.Println(ZTree[branchindex[0]])
	branchmult := new(fieldVal)
	for i := 0; i < 15; i++ {
		if i == 0 {
			branchmult.Mul2(ZTree[branchindex[i]], ZTree[branchindex[i+1]])
		} else {
			branchmult.Mul2(branchmult, ZTree[branchindex[i+1]])
		}
	}
	//fmt.Println(branchmult)
	//fmt.Println(ZTree[branchindex[0]])\
	return branchmult
}
*/

func GetTreeBranchMult(branchindex [12]int) *fieldVal {
	branchmult := new(fieldVal)
	branchmult.Set(ZTree[branchindex[0]])
	for i := 1; i < 1; i++ {
		branchmult.Mul2(branchmult, ZTree[branchindex[i]])
	}
	return branchmult
}

func Encrypt(pubkey *PublicKey, m []byte) (*big.Int, *big.Int, *big.Int, *big.Int) {
	c := S256()
	r, _ := NewPrivateKey(c)
	rpkx, rpky := c.ScalarMult(pubkey.X, pubkey.Y, r.D.Bytes())
	mGx, mGy := c.ScalarMult(c.Gx, c.Gy, m)
	c2x := new(big.Int)
	c2y := new(big.Int)
	c2x, c2y = c.Add(mGx, mGy, rpkx, rpky)
	return r.PublicKey.X, r.PublicKey.Y, c2x, c2y
}

//使用树解密，还需继续优化
/*
func Decrypt(priv *PrivateKey, c1x *big.Int, c1y *big.Int, c2x *big.Int, c2y *big.Int) (int64, error) {
	c := S256()
	var m int64 = -1
	skc1x, skc1y := c.ScalarMult(c1x, c1y, priv.D.Bytes())
	inv_skc1y := new(big.Int)
	inv_skc1y.Add(c.P, inv_skc1y)
	inv_skc1y.Sub(inv_skc1y, skc1y)
	mGx, mGy := c.Add(c2x, c2y, skc1x, inv_skc1y)
	fmGx, fmGy := c.bigAffineToField(mGx, mGy)
	fleftx, flefty := new(fieldVal), new(fieldVal)
	zs := make([]*fieldVal, 4096)
	for i := 0; i < 4096; i++ {
		z := new(fieldVal)
		z.SetInt(1)
		ft2x := T2x[i]
		c.Getz3(fmGx, ft2x, z)
		zs[i] = z
	}
	treeroot := BuildTree(zs)
	treeroot_inv := new(fieldVal)
	treeroot_inv.Set(treeroot).Inverse()
	var j int64 = 0
	for ; j < 4096; j++ {
		if j == 0 {
			sum := sha256.Sum256([]byte(mGx.String() + mGy.String()))
			var sum64 [8]byte
			copy(sum64[:], sum[:8])
			if i, ok := T1[sum64]; ok {
				m = i
				break
			}
		}
		inv_z := new(fieldVal)
		ft2x, ft2y := T2x[j], T2y[j]
		branchindex := GetTreeBranch(int(j))
		branchmult := GetTreeBranchMult(branchindex)
		inv_z.Mul2(treeroot_inv, branchmult)
		c.Getx3y3(fmGx, fmGy, ft2x, ft2y, fleftx, flefty)
		leftx, lefty := c.fieldJacobianToBigAffineWithoutInv(fleftx, flefty, inv_z)
		sum := sha256.Sum256([]byte(leftx.String() + lefty.String()))
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		if i, ok := T1[sum64]; ok {
			m = j*4096 + i
			break
		}
	}


		TestmGx, TestmGy := c.ScalarBaseMult(big.NewInt(m).Bytes())
		r1 := mGx.Cmp(TestmGx)
		r2 := mGy.Cmp(TestmGy)
		if r1 == 0 && r2 == 0 {
			return m, nil
		}


	return m, nil
}
*/

var Cost1 time.Duration = 0
var Cost2 time.Duration = 0
var Cost3 time.Duration = 0
var Cost4 time.Duration = 0
var Cost5 time.Duration = 0
var Cost6 time.Duration = 0
var Cost7 time.Duration = 0
var Cost8 time.Duration = 0
var Cost9 time.Duration = 0

//两颗树解密
/*
func Decrypt(priv *PrivateKey, c1x *big.Int, c1y *big.Int, c2x *big.Int, c2y *big.Int) (int64, error) {
	c := S256()
	var m int64 = -1

	start1 := time.Now()
	skc1x, skc1y := c.ScalarMult(c1x, c1y, priv.D.Bytes())
	cost1 := time.Since(start1)
	Cost1 = Cost1 + cost1

	start2 := time.Now()
	inv_skc1y := new(big.Int)
	inv_skc1y.Add(c.P, inv_skc1y)
	inv_skc1y.Sub(inv_skc1y, skc1y)
	cost2 := time.Since(start2)
	Cost2 = Cost2 + cost2

	start3 := time.Now()
	mGx, mGy := c.Add(c2x, c2y, skc1x, inv_skc1y)
	cost3 := time.Since(start3)
	Cost3 = Cost3 + cost3

	fmGx, fmGy := c.bigAffineToField(mGx, mGy)
	//fleftx := new(fieldVal)
	zs := make([]*fieldVal, 8192)
	start4 := time.Now()
	for i := 0; i < 8192; i++ {
		z := new(fieldVal)
		z.SetInt(1)
		ft2x := T2x[i]
		c.Getz3(fmGx, ft2x, z)
		zs[i] = z
	}
	cost4 := time.Since(start4)
	Cost4 = Cost4 + cost4

	start5 := time.Now()
	treeroot := BuildTree(zs)
	cost5 := time.Since(start5)
	Cost5 = Cost5 + cost5

	start6 := time.Now()
	treeroot_inv := new(fieldVal)
	treeroot_inv.Set(treeroot).Inverse()
	cost6 := time.Since(start6)
	Cost6 = Cost6 + cost6

	start7 := time.Now()
	GetInvTree(treeroot_inv)
	cost7 := time.Since(start7)
	Cost7 = Cost7 + cost7

	var j int64 = 0
	for ; j < 8192; j++ {
		if j == 0 {
			start8 := time.Now()
			sum := sha256.Sum256([]byte(mGx.String()))
			var sum64 [8]byte
			copy(sum64[:], sum[:8])

			i, ok := T1[sum64]
			cost8 := time.Since(start8)
			Cost8 = Cost8 + cost8
			if ok {
				m = i
				break
			}
		}
		ft2x, ft2y := T2x[j], T2y[j]
		start9 := time.Now()
		leftx := c.Getx3(fmGx, fmGy, ft2x, ft2y, ZinvTree[j])
		//leftx := c.fieldJacobianToBigAffineXWithoutInv(fleftx)
		cost9 := time.Since(start9)
		Cost9 = Cost9 + cost9

		start8 := time.Now()
		sum := sha256.Sum256([]byte(leftx.String()))
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		i, ok := T1[sum64]
		cost8 := time.Since(start8)
		Cost8 = Cost8 + cost8
		if ok {
			m = j*67108864 + i
			break
		}
	}


	TestmGx, TestmGy := c.ScalarBaseMult(big.NewInt(m).Bytes())
	r1 := mGx.Cmp(TestmGx)
	r2 := mGy.Cmp(TestmGy)

	if r1 == 0 && r2 == 0 {
		return m, nil
	}
	return -1, nil
	//return m, nil
}
*/

//不加树使用hash表解密

func Decrypt(priv *PrivateKey, c1x *big.Int, c1y *big.Int, c2x *big.Int, c2y *big.Int) (int, error) {
	c := S256()
	m := -1
	skc1x, skc1y := c.ScalarMult(c1x, c1y, priv.D.Bytes())
	inv_skc1y := new(big.Int)
	inv_skc1y.Add(c.P, inv_skc1y)
	inv_skc1y.Sub(inv_skc1y, skc1y)
	mGx, mGy := c.Add(c2x, c2y, skc1x, inv_skc1y)
	j := 0
	z := new(fieldVal)
	z.SetInt(1)
	for ; j < 256; j++ {
		if j == 0 {
			sum := sha256.Sum256([]byte(mGx.String()))
			var sum64 [8]byte
			copy(sum64[:], sum[:8])
			if i, ok := T1[sum64]; ok {
				m = int(i)
				break
			}
		}
		t2x, t2y := c.fieldJacobianToBigAffine(T2x[j], T2y[j], z)
		leftx, _ := c.Add(mGx, mGy, t2x, t2y)
		sum := sha256.Sum256([]byte(leftx.String()))
		var sum64 [8]byte
		copy(sum64[:], sum[:8])
		if i, ok := T1[sum64]; ok {
			m = j*256 + int(i)
			break
		}
	}
	return m, nil
}

//双循环解密，已废弃
// Decrypt decrypts data that was encrypted using the Encrypt function.
/*
func Decrypt(priv *PrivateKey, c1x *big.Int, c1y *big.Int, c2x *big.Int, c2y *big.Int) (int, error) {
	c := S256()
	skc1x, skc1y := c.ScalarMult(c1x, c1y, priv.D.Bytes())
	mGx := c2x.Sub(c2x, skc1x)
	mGy := c2y.Sub(c2y, skc1y)
	T12x := new(big.Int)
	T12y := new(big.Int)
	var rx = 2
	var ry = 2
	i := 1
	j := 0
	t3x, t3y, t3z, t1z := new(fieldVal), new(fieldVal), new(fieldVal), new(fieldVal)
	t1z.SetInt(1)
	for ; j <= 65535; j++ {
		for i = 1; i <= 65536; i++ {
			if j == 0 {
				rx = mGx.Cmp(T1x[i])
				ry = mGy.Cmp(T1y[i])
			} else {
				t1x, t1y := c.bigAffineToField(T1x[i], T1y[i])
				t2x, t2y := c.bigAffineToField(T2x[j], T2y[j])
				c.addZ1AndZ2EqualsOne(t1x, t1y, t1z, t2x, t2y, t3x, t3y, t3z)
				T12x, T12y = c.fieldJacobianToBigAffine(t3x, t3y, t3z)
				rx = mGx.Cmp(T12x)
				ry = mGy.Cmp(T12y)
			}
			if rx == 0 && ry == 0 {
				break
			}
		}
		if rx == 0 && ry == 0 {
			break
		}
	}
	m := i + 65536*j
	return m, nil
}
*/

// Implement PKCS#7 padding with block size of 16 (AES block size).

// addPKCSPadding adds padding to a block of data
func addPKCSPadding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// removePKCSPadding removes padding from data that was added with addPKCSPadding
func removePKCSPadding(src []byte) ([]byte, error) {
	length := len(src)
	padLength := int(src[length-1])
	if padLength > aes.BlockSize || length < aes.BlockSize {
		return nil, errInvalidPadding
	}

	return src[:length-padLength], nil
}

/*
func init() {
	c := S256()
	var i int64 = 1
	var j int64 = 0
	//var k int64 = 1
	//16777216,4096
	for ; i <= 65536; i++ {
		ibigint := big.NewInt(i)
		T1x[i], T1y[i] = c.ScalarMult(c.Gx, c.Gy, ibigint.Bytes())
	}
	//65536,256
	for ; j <= 65535; j++ {
		jbigint := big.NewInt(j)
		//fmt.Println(jbigint.String())
		T2x[j], T2y[j] = c.ScalarMult(T1x[65536], T1y[65536], jbigint.Bytes())
	}
}
*/

/*
func init() {
	c := S256()
	var i int64 = 1
	var j int64 = 0
	//var k int64 = 1
	//16777216,4096
	file, err := os.Open("T1.txt")
	if err != nil {
		panic(err)
	}
	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		if err != nil || io.EOF == err {
			break
		} else {
			line = strings.Replace(line, "\n", "", -1)
			line = strings.Replace(line, "[", "", -1)
			line = strings.Replace(line, "]", "", -1)
			data := strings.Fields(line)
			var sum64 [8]byte
			for i := 0; i < 8; i++ {
				value, _ := strconv.Atoi(data[i])
				sum64[i] = uint8(value)
			}
			T1[sum64] = i
			i++
			fmt.Println(i)
		}
	}
	t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(16777216).Bytes())
	for ; j < 4096; j++ {
		fmt.Printf("%d\n", j)
		jbigint := big.NewInt(-j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.P, inv_t2y)
		inv_t2y.Sub(inv_t2y, t2y)
		ft2x, ft2y := c.bigAffineToField(t2x, inv_t2y)
		T2x[j] = ft2x
		T2y[j] = ft2y
	}
}
*/

/*
func init() {
	c := S256()
	var i int64 = 2
	var j int64 = 0
	//var k int64 = 1
	//16777216,4096
	x := big.NewInt(0)
	x.Add(c.Gx, x)
	y := big.NewInt(0)
	y.Add(c.Gy, y)


	T1[c.Gx.String()] = 1
	for ; i <= 16777216; i++ {
		fmt.Printf("%d\n", i)
		x, y = c.Add(x, y, c.Gx, c.Gy)
		//x1 := big.NewInt(0)
		//x1.Add(x1, x)
		//T1.InsertStringKey(x.String(), int(i))

		T1[x.String()] = i
	}
	//t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(4096).Bytes())
	t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(16777216).Bytes())
	for ; j < 4096; j++ {
		fmt.Printf("%d\n", j)
		jbigint := big.NewInt(-j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.P, inv_t2y)
		inv_t2y.Sub(inv_t2y, t2y)
		ft2x, ft2y := c.bigAffineToField(t2x, inv_t2y)
		T2x[j] = ft2x
		T2y[j] = ft2y
	}
}
*/

/*
func init() {
	c := S256()
	var i int64 = 1
	var j int64 = 0
	//var k int64 = 1
	//16777216,4096
	file, err := os.Open("/home/lgw/go/src/github.com/btcsuite/btcd/btcec/Tx26.txt")
	if err != nil {
		panic(err)
	}
	rd := bufio.NewReader(file)
	for {
		line, err := rd.ReadString('\n')
		if err != nil || io.EOF == err {
			break
		} else {
			line = strings.Replace(line, "\n", "", -1)
			line = strings.Replace(line, "[", "", -1)
			line = strings.Replace(line, "]", "", -1)
			data := strings.Fields(line)
			var sum64 [8]byte
			for i := 0; i < 8; i++ {
				value, _ := strconv.Atoi(data[i])
				sum64[i] = uint8(value)
			}
			T1[sum64] = i
			fmt.Println(i)
			if i == 16777216 {
				break
			}
			i++
		}
	}
	file.Close()
	t1lastx, t1lasty := c.ScalarMult(c.Gx, c.Gy, big.NewInt(16777216).Bytes())
	for ; j < 256; j++ {
		fmt.Printf("%d\n", j)
		jbigint := big.NewInt(-j)
		t2x, t2y := c.ScalarMult(t1lastx, t1lasty, jbigint.Bytes())
		inv_t2y := new(big.Int)
		inv_t2y.Add(c.P, inv_t2y)
		inv_t2y.Sub(inv_t2y, t2y)
		ft2x, ft2y := c.bigAffineToField(t2x, inv_t2y)
		T2x[j] = ft2x
		T2y[j] = ft2y
	}
}
*/
