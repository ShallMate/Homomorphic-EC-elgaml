package btcec

import (
	"fmt"
	"math/big"
	"time"
)

var testdata = make([]*PrivateKey, 4096)
var testfieldx = make([]*fieldVal, 4096)
var testfieldy = make([]*fieldVal, 4096)

//计算仿射坐标下的k*G
func TestKG() {
	c := S256()
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		_, _ = c.ScalarMult(c.Gx, c.Gy, testdata[i].D.Bytes())
	}
	cost1 := time.Since(start1)
	fmt.Printf("k*G 4096 num cost=[%s]\n", cost1)
}

// 访射坐标求-P
func Test_P() {
	c := S256()
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		inv_P := new(big.Int)
		inv_P.Add(c.P, inv_P)
		inv_P.Sub(inv_P, testdata[i].PublicKey.Y)
	}
	cost1 := time.Since(start1)
	fmt.Printf("-P  4096 num cost=[%s]\n", cost1)
}

//雅可比坐标到仿射坐标
func Test_F_to_B() {
	c := S256()
	z := new(fieldVal)
	z.SetInt(1)
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		_, _ = c.fieldJacobianToBigAffine(testfieldx[i], testfieldy[i], z)
	}
	cost1 := time.Since(start1)
	fmt.Printf("雅可比到访射坐标  4096 num cost=[%s]\n", cost1)
}

//访射坐标到雅可比坐标
func Test_B_to_F() {
	c := S256()
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		testfieldx[i], testfieldy[i] = c.bigAffineToField(testdata[i].PublicKey.X, testdata[i].PublicKey.Y)
	}
	cost1 := time.Since(start1)
	fmt.Printf("仿射到雅可比坐标  4096 num cost=[%s]\n", cost1)
}

//雅可比坐标求逆
func F_Inverse() {
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		testfieldx[i].Inverse()
	}
	cost1 := time.Since(start1)
	fmt.Printf("雅可比坐标求逆  4096 num cost=[%s]\n", cost1)
}

//雅可比坐标相加
func F_Add() {
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		testfieldx[i].Add(testfieldy[i])
	}
	cost1 := time.Since(start1)
	fmt.Printf("雅可比坐标相加  4096 num cost=[%s]\n", cost1)
}

func TestGetBranchIndex() {
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		GetTreeBranch(i)
	}
	cost1 := time.Since(start1)
	fmt.Printf("得到branchindex  4096 num cost=[%s]\n", cost1)
}

func F_Mul() {
	start1 := time.Now()
	for i := 0; i < 4096; i++ {
		testfieldx[i].Mul2(testfieldx[i], testfieldy[i])
	}
	cost1 := time.Since(start1)
	fmt.Printf("雅可比坐标相乘  4096 num cost=[%s]\n", cost1)
}

func TestTime() {
	c := S256()
	for i := 0; i < 4096; i++ {
		testdata[i], _ = NewPrivateKey(c)
	}
	TestKG()
	Test_B_to_F()
	F_Mul()
	F_Add()
	F_Inverse()
	TestGetBranchIndex()
	Test_F_to_B()
	Test_P()
}
