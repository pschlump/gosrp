package gosrp

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/pschlump/HashStrings"
	"github.com/pschlump/godebug"
	"github.com/pschlump/gosrp/big" // "./big" // "math/big"
)

// "crypto/hmac"
// cryptorand "crypto/rand"
// "crypto/sha256"
// "crypto/subtle"
// "fmt"
// "io"
// mathrand "math/rand"

/*

From: http://srp.stanford.edu/ndss.html

(With additional notes by me)

The SRP Protocol
================

What follows is a complete description of the entire SRP authentication process from beginning to end, starting with the password setup steps.

			Table 3: Mathematical Notation for SRP
			---------------------------------------

		Var		Description

		n	   	A large prime number. All computations are performed modulo n.
		g	   	A primitive root modulo n (often called a generator)		- this is 2 or 5 - from the table based on bitsize
		N		Modulo number												- big number from table - use based on standard (js/rfc5054-2048-sha256.js)
																			- this is really the same as 'n'
		s	   	A random string used as the user's salt
		P	   	The user's password
		x	   	A private key derived from the password and salt
		v	   	The host's password verifier
		u	   	Random scrambling parameter, publicly revealed 				- (hash of A.B)
		a,b	   	Ephemeral private keys, generated randomly and not publicly revealed
		A,B	   	Corresponding public keys
				Client: A = g^a, compute and send A to server
				Server: B = v + g^b
		H()	   	One-way hash function. 										-  In this H() will be Sha256
		m,n	   	The two quantities (strings) m and n concatenated
		K	   	Session key

		C		Carol's Username (carol@example.com, also referred to as I in some cases)
		D.B.	Database
		t		Random UUID used as salt for generating session ID in steps 9,10
		r		Random UUID with timeout for keeping data during authorization

Table 3 shows the notation used in this section. The values n and g are well-known values, agreed to beforehand.

To establish a password P with Steve, Carol picks a random salt s, and computes 		- In this this is registration of new user or password change

		x = H(s, P)
		v = g^x

Steve stores v and s as Carol's password verifier and salt. Remember that the computation of v is implicitly reduced modulo n. x is
discarded because it is equivalent to the plaintext password P.

The AKE protocol also allows Steve to have a password z with a corresponding public key held by Carol; in SRP, we set z = 0 so
that it drops out of the equations. Since this private key is 0, the corresponding public key is 1. Consequently, instead of
safeguarding its own password z, Steve needs only to keep Carol's verifier v secret to assure mutual authentication. This frees Carol
from having to remember Steve's public key and simplifies the protocol.

To authenticate, Carol and Steve engage in the protocol described in Table 4. A description of each step follows:

			Table 4: The Secure Remote Password Protocol
			--------------------------------------------

		Step	Carol				Communication				Steve
		1.								C -->					(lookup s, v from D.B. by username(C)) - send back s		/api/srp_login
		2.		x = H(s, P)				<-- s, t, r				t is 2nd salt sent back to client
																r is 3rd random - temporary for saving data
																In D.B. create the key(r){C,t,s,v} + Timeout
																In D.B. create the key(t){C,r} Session Key

		3.		A = g^a					A,r -->																				/api/srp_confirm
																Fetch from d.b. using(r){C,t,s,v}
		4.								<-- B, u				B = v + g^b			Lookup D.B. (C), get s,v - gen b      ?? u
		5.		S = (B - g^x)^(a + ux)							S = (A · v^u)^b		Both sides can now compute S
		6.		K = H(S)										K = H(S)			Both sides compute the same K - Update D.B. with A,B,b,K
																In d.b. Update(r){C,t,s,v,B,S,K,M,K}

		7.		M[1] = H(A, B, K)		M[1],r -->				(verify M[1])		Lookup D.B. getting s, A, B, b, K		/api/srp_verify
		8.		(verify M[2])			<-- M[2]				M[2] = H(A, M[1], K)

		9.		U = H(t,K)										U = H(t,K)			Generate session ID, store K, C, s, info in D.B. with key U
		10.		Use U as key for communication
				(Encrypt with K)								(Decrypt with K) (Encrypt Responses with K)
				(Decrypt with K)
																Update(t) with logged in


1. Carol sends Steve her username, (e.g. carol@example.com).
	Example #8
2. Steve looks up Carol's password entry and fetches her password verifier v and her salt s. He sends s to Carol.
	Carol computes her long-term private key x using s and her real password P.
	Example s=#13, v=??
		var v = xxx.generateVerifier(s,identity,password);
		The verifier is computed as v = g^x (mod N).
		g=#2, N=#1000001
		x=??
3. Carol generates a random number a, 1 < a < n, computes her ephemeral public key A = g^a, and sends it to Steve.
4. Steve generates his own random number b, 1 < b < n, computes his ephemeral public key B = v + g^b, and sends
	it back to Carol, along with the randomly generated parameter u.
5. Carol and Steve compute the common exponential value S = g^(ab + bux) using the values available to each of them.
	If Carol's password P entered in Step 2 matches the one she originally used to generate v, then both values of
	S will match.
6. Both sides hash the exponential S into a cryptographically strong session key.
7. Carol sends Steve M[1] as evidence that she has the correct session key. Steve computes M[1] himself and verifies
	that it matches what Carol sent him.
8. Steve sends Carol M[2] as evidence that he also has the correct session key. Carol also verifies M[2] herself,
	accepting only if it matches Steve's value.

This protocol is mostly the result of substituting the equations of Section 3.2.1 into the generic AKE protocol, adding explicit
flows to exchange information like the user's identity and the salt s. Both sides will agree on the session key S = g^(ab + bux) if all
steps are executed correctly. SRP also adds the two flows at the end to verify session key agreement using a one-way hash function.
Once the protocol run completes successfully, both parties may use K to encrypt subsequent session traffic.

Version 0.0.1

https://github.com/RuslanZavacky/srp-6a-demo/blob/master/srp/Server/Srp.php
https://github.com/RuslanZavacky/srp-6a-demo
https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol
http://srp.stanford.edu/analysis.html
https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol -- Shows how to gen the B, A key

Package hmac implements the Keyed-Hash Message Authentication Code
(HMAC) as defined in U.S. Federal Information Processing Standards
Publication 198. An HMAC is a cryptographic hash that uses a key
to sign a message. The receiver verifies the hash by recomputing
it using the same key.


https://github.com/RuslanZavacky/srp-6a-demo/blob/master/srp/Client/lib/srp.js -- Client side code - good
Local: /Users/corwin/Projects/tab-server1/SrpDemo/php/srp-6a-demo

*/

// Reorg into 'S' and 'I' value sets so 'S' is JSON/searializable

type GoSrp struct {
	State         int
	XBits         int
	Auth          bool
	fixRandomFlag bool
	randomStr     string

	//
	Key_s   string
	Salt_s  string
	XA_s    string
	Xa_s    string
	XB_s    string
	Xb_s    string
	XHAMK_s string
	XI_s    string
	Xk_s    string
	XM1_s   string
	XM2_s   string
	XS_s    string
	Xu_s    string
	Xv_s    string
	XN_s    string
	Xg_s    string
	//
	Salt *big.Int
	XA   *big.Int
	Xa   *big.Int
	Xavu *big.Int
	XB   *big.Int
	Xb   *big.Int
	Xg   *big.Int
	Xk   *big.Int
	XN   *big.Int
	XS   *big.Int
	Xu   *big.Int
	Xv   *big.Int
}

// xyzzyBits // this is the function to change for different bit sizes - returns g,N - set in process, needs to set "bits" to value

func GoSrpNew(C string, xBits int) *GoSrp {

	s1, ok := pflist_str[xBits]
	if !ok {
	}

	N, ok := big.NewInt(0).SetString(s1.N, s1.NBase)
	if !ok {
		panic("Unable to convert const string to bigInt - internal error")
	}

	// g, err := strconv.ParseInt(s1[0], 10, 64)
	g, ok := big.NewInt(0).SetString(s1.G, s1.GBase)
	if !ok {
		panic("Unable to convert const string to bigInt - internal error")
	}

	return &GoSrp{
		State: 0,
		XI_s:  C,
		Xg:    g,
		Xg_s:  g.HexString(),
		XN:    N,
		XN_s:  N.HexString(),
		XBits: xBits,
	}
}

var bits = 2048

var g_db_pos = 0

// GenerateVerifier takes passowrd and computes the verifier and the salt and returns them.
//
// Go Client Side.
//
// To establish a password P with Steve, Carol picks a random salt s, and computes 		- In this this is registration of new user or password change
//
// 		x = H(s, P)
// 		v = g^x
//
// Steve stores v and s as Carol's password verifier and salt. Remember that the computation of v is implicitly reduced modulo n. x is
// discarded because it is equivalent to the plaintext password P.
//

func (gs *GoSrp) GenerateVerifier(username, password string) (verifier string, salt string) {
	/*

	   // Generate a new SRP verifier. Password is the plaintext password.
	   //
	   // options is optional and can include:
	   //   in for testing.  Random UUID if not provided.
	   // - salt: String. A salt to use.  Mostly this is passed in for
	   //   testing.  Random UUID if not provided.
	   // - SRP parameters (see _defaults and paramsFromOptions below)
	   _srp.generateVerifier = function (username, password, options) {
	   	var params = paramsFromOptions(options);

	   	var salt = (options && options.salt) || random16byteHex.random();

	   	if ( _srp_debug1 ) {
	   		salt = "6b6e1eda7efb668c36ebf95c107300a3";
	   	}

	   	var ix_s = salt + username + password;		// this fails to match with RFC2945 where x = H ( s | H ( I | ":" | P ) )
	   	var x = params.hash(salt + username + password);
	   	var xi = new BigInteger(x, 16);
	   	var v = params.g.modPow(xi, params.N);
	   	var vStr = v.toString(16);

	   	if ( _srp_debug1 ) {
	   		console.log ( "salt=", salt);
	   		console.log ( "username=", username);
	   		console.log ( "password=", password);
	   		console.log ( "x=", xi.toString(16));
	   		console.log ( "    ix_s = ["+ix_s+"]" );
	   		console.log ( "    x_s = ["+x+"]" );
	   		console.log ( "g=", params.g.toString(16) );
	   		console.log ( "N=", params.N.toString(16));
	   		console.log ( "v=", vStr)
	   		// x = H(s, I, p)       # Private key
	   		// v = pow(g, x, N)     # Password verifier
	   	}

	   	if ( _srp_debug1 ) {
	   		if ( salt === "6b6e1eda7efb668c36ebf95c107300a3" ) {
	   			var vRef = "aa4495a557a7a5b047f5bffba993e456ffdc530476554d76641e75179b83dcecafa5b4fa9cd6fbdded13e68c736a0701f3a9765e536d875a6e9c6946d141305ed95ae48579d83a3ab06c79b0be0d276b9d8c39078c8b601608db3bb747b9ec70532ed614af1a5923f0e28ba93579a5e2d057ffb83b8b9b55aa354f8ed9d107fd628e1a746df35ef948815e24d7a4f505eb68f7bd05bef55c6c5ee2cf0c26d1c8be150d4479fa2e4816a74df4f2716e0f24077d3d589104f19a61576fd3d920421eec73bb52549f39cd777147abf727d9b77094aa037ba30851caeb1260186fae83f81b707bb566e4888f6a23c8d3c52de5a8ab2cac6274b5842109235d963299";
	   			if ( vStr === vRef ) {
	   				console.log ( "Looks like correct v" );
	   			} else {
	   				console.log ( "FAIL - incorrect v" );
	   			}
	   		}
	   	}

	   	return {
	   		salt:salt,
	   		verifier:vStr
	   	};
	   };
	*/

	salt_b, err := GenRandBytes(16)
	if err != nil {
	}

	salt = fmt.Sprintf("%x", salt_b) // 32 bytes of salt

	if dbTestingMode && gs.fixRandomFlag {
		salt = gs.randomStr
	}

	// var ix_s = salt + username + password;		// this fails to match with RFC2945 where x = H ( s | H ( I | ":" | P ) )
	// ix_s := salt + username + password
	// ix_s := salt + username + password
	// var x = params.hash(salt + username + password);

	//  RFC2945 specifies x = H ( s | H ( I | ":" | P ) ) -- Note s|H(I|":"|P) - no colon between s|H
	x := HashStrings.HashStrings(salt, HashStrings.HashStrings(username, ":", password))

	// var xi = new BigInteger(x, 16);
	xi, ok := big.NewInt(0).SetString(x, 16)
	if !ok {
		fmt.Printf("Failed to convert x=[%s] to big int\n", x)
	}

	// 		v = g^x
	// var v = params.g.modPow(xi, params.N);
	v := big.NewInt(0).Exp(gs.Xg, xi, gs.XN) // g^x modulo N

	// var vStr = v.toString(16);
	verifier = v.HexString()

	return
}

func GenRandBytes(nRandBytes int) (buf []byte, err error) {
	if dbCipher {
		fmt.Printf("AT: %s\n", godebug.LF())
	}
	buf = make([]byte, nRandBytes)
	_, err = rand.Read(buf)
	if err != nil {
		fmt.Printf(`{"msg":"Error generaintg random numbers :%s"}\n`, err)
		return nil, err
	}
	// fmt.Printf("Value: %x\n", buf)
	return
}

func GenRandNumber(nDigits int) (buf string, err error) {

	var n int64
	for {
		binary.Read(rand.Reader, binary.LittleEndian, &n)
		if n < 0 {
			n = -n
		}
		if n > 1000000 {
			break
		}
		// fmt.Printf("Looping GenRandNumber=%d\n", n)
	}
	// fmt.Printf("Big Eenough GenRandNumber=%d\n", n)
	n = n % 100000000
	// fmt.Printf("GenRandNumber=%d\n", n)
	buf = fmt.Sprintf("%08d", n)
	// fmt.Printf("GenRandNumber buf=%s\n", buf)

	return
}

// /api/spr_login
// match with __construct
// *_s is base 16 string representation of value.
// Names are prefixed with 'X' to make them searchable in code.
// set 	Salt, Salt_s
//     	Xv, Xv_s
//     	Xk, Kx_s = Hash( XN || Xg )
//		Xb, Xb_s = random value, checked for unlikely error
//
func (gs *GoSrp) Setup(verifier string, salt string) {
	zero := big.NewInt(0)
	ok := false

	gs.State = 1
	gs.Salt_s = salt

	if dbTestingMode && gs.fixRandomFlag {
		gs.Salt_s = gs.randomStr
	}

	gs.Salt, ok = big.NewInt(0).SetString(gs.Salt_s, 16)
	gs.Xv_s = verifier
	gs.Xv, ok = big.NewInt(0).SetString(gs.Xv_s, 16)
	if !ok {
		fmt.Printf("Error on convert of string to big, variable v \n")
		panic("")
	}
	if db8 {
		fmt.Printf("Hash=%s\n", HashStrings.HashStrings(gs.XN.HexString()+gs.Xg.HexString()))
	}
	// gs.Xk, ok = big.NewInt(0).SetString(HashStrings.HashStrings(gs.XN.HexString()+gs.Xg.HexString()), 16) // questionalble, k=H(N || g)
	gs.Xk, ok = big.NewInt(0).SetString(HashStrings.HashStrings(gs.XN_s, ":", gs.Xg_s), 16)
	gs.Xk_s = gs.Xk.HexString()
	if !ok {
		fmt.Printf("Error on convert of string to big, variable k\n")
		panic("")
	}
	gs.Key_s = ""
	for {
		gs.Xb = randlong(bits)
		gs.Xb_s = gs.Xb.HexString()

		if dbTestingMode && gs.fixRandomFlag {
			gs.Xb_s = gs.randomStr
			gs.Xb, _ = big.NewInt(0).SetString(gs.Xb_s, 16)
		}

		// 4.								<-- B, u				B = v + g^b			Lookup D.B. (C), get s,v - gen b      ?? u
		gPowed := big.NewInt(0).Exp(gs.Xg, gs.Xb, gs.XN) // g^b modulo N
		t1 := big.NewInt(0).Mul(gs.Xk, gs.Xv)            // k*v
		t2 := big.NewInt(0).Add(t1, gPowed)              // (k*v) + (B == g^b)
		gs.XB = big.NewInt(0).Mod(t2, gs.XN)             // modulo N

		tf := big.NewInt(0).Mod(gs.XB, gs.XN) // check B % N not equal to zero, if it is 0, then generate new random 'b' value
		if tf.Cmp(zero) != 0 {
			break
		}
	}
	gs.XB_s = gs.XB.HexString() // save XB_s, from XB

}

func (gs *GoSrp) CalculateA() string {
	zero := big.NewInt(0)

	for {
		gs.Xa = randlong(bits)
		gs.Xa_s = gs.Xa.HexString()

		if dbTestingMode && gs.fixRandomFlag {
			gs.Xa_s = gs.randomStr
			gs.Xa, _ = big.NewInt(0).SetString(gs.Xa_s, 16)
		}

		gPowed := big.NewInt(0).Exp(gs.Xg, gs.Xa, gs.XN)
		gs.XA = gPowed

		tf := big.NewInt(0).Mod(gs.XA, gs.XN)
		if tf.Cmp(zero) != 0 {
			break
		}
	}

	gs.XA_s = gs.XA.HexString() // XA_s = XA
	gs.State = 2

	return gs.XA_s
}

// -------------------------------------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------------------------------------
// -------------------------------------------------------------------------------------------------------------------------------------------------
// /api/spr_challenge
// Input:
//		A
// Output:
//		M1, B
func (gs *GoSrp) IssueChallenge(A_s string) {
	zero := big.NewInt(0)
	ok := true

	gs.XA, ok = big.NewInt(0).SetString(A_s, 16)
	if !ok {
		fmt.Printf("A did not parse - error, [%s]\n", A_s)
		panic("")
	}
	gs.XA_s = gs.XA.HexString()
	if gs.XA_s != A_s {
		fmt.Printf("Bad conversion\n")
		panic("")
	}

	tf := big.NewInt(0).Mod(gs.XA, gs.XN)
	if tf.Cmp(zero) == 0 {
		fmt.Printf("Bad A Value - error, %s\n", gs.XA.HexString())
		panic("")
	}

	fmt.Printf("gosrp: A [%s] B [%s], hash [%s], %s\n", gs.XA_s, gs.XB_s, HashStrings.HashStrings(gs.XA_s+gs.XB_s), godebug.LF()) //

	u, ok := big.NewInt(0).SetString(HashStrings.HashStrings(gs.XA_s, ":", gs.XB_s), 16)      // ///////////////////////// xyzzy // xyzzySep20-2016 - probably wrong on next line.
	fmt.Printf("gospr: <<<CRITICAL>>>  H(A+B) = u = [%s], %s\n", u.HexString(), godebug.LF()) //
	t1 := big.NewInt(0).Set(gs.XA)                                                            //
	t2 := big.NewInt(0).Exp(gs.Xv, u, gs.XN)                                                  //
	avu := big.NewInt(0).Mul(t1, t2)                                                          //
	gs.XS = big.NewInt(0).Exp(avu, gs.Xb, gs.XN)                                              // matched w/ python
	gs.XS_s = gs.XS.HexString()                                                               //
	gs.Key_s = HashStrings.HashStrings(gs.XS_s)                                               //	!!!!!!!!!!!!!!!!! final key, gs.Key_s, shared between client/server !!!!!!!!!!!!!!!!!

	if dbDumpKeyToLog {
		fmt.Fprintf(os.Stderr, "gosrp: <<<CRITICAL>>>  S Must be SAME!  S [%s] Key [%s]\n", gs.XS_s, gs.Key_s) // matched w/ python
	}

	gs.XM1_s = HashStrings.HashStrings(gs.XA_s, ":", gs.XB_s, ":", gs.Key_s) // xyzzy - error - check RFC, missing ":" in concat?

	gs.Xu = u
	gs.Xu_s = u.HexString()
	gs.Xavu = avu
	gs.State = 3

	_ = ok
}

// Input M1 (from client), A, K
func (gs *GoSrp) CalculateM2(ClientM1 string) (auth bool, M2_s string) {
	gs.State = 4
	auth = false
	// gs.M1_s - calculate
	//	7.		M[1] = H(A, B, K)		M[1],r -->				(verify M[1])		Lookup D.B. getting s, A, B, b, K
	//	8.		(verify M[2])			<-- M[2]				M[2] = H(A, M[1], K)
	// gs.XM1_s = HashStrings.HashStrings(gs.XA_s + gs.XB_s + gs.Key_s)
	gs.XM2_s = HashStrings.HashStrings(gs.XA_s, ":", gs.XM1_s, ":", gs.Key_s)
	gs.XHAMK_s = HashStrings.HashStrings(gs.XA_s + gs.XM2_s + gs.XS_s)
	// if subtle.ConstantTimeCompare ( []byte(gs.XM1_s), []byte(ClientM1) ) == 1 { // xyzzy - constant time compare
	if gs.XM1_s == ClientM1 { // xyzzy - constant time compare
		auth = true
	}
	gs.Auth = auth
	return auth, gs.XM2_s
}

/*
	echo "ST/bits=  [{$this->ST}/{$this->bits}]\n\n";
	echo "verifier= [{$this->verifier}]\n\n";
	echo "salt=     [{$this->salt}]\n\n";
	echo "Nhex=     [{$this->Nhex}]\n\n";
	echo "g=        [{$this->g}]\n\n";
	echo "khex=     [{$this->khex}]\n\n";
	echo "vhex=     [{$this->vhex}]\n\n";
	echo "key=      [{$this->key}]\n\n";
	echo "bhex=     [{$this->bhex}]\n\n";
	echo "Bhex=     [{$this->Bhex}]\n\n";
*/
func (gs *GoSrp) TestDump1() {
	if db8 {
		// Salt   *big.Int
		// Xv     *big.Int
		// XN     *big.Int
		// Xg     *big.Int
		// Xk     *big.Int
		// Xb     *big.Int
		// XB     *big.Int
		fmt.Printf("ST/bits=  [%d/%d]\n\n", gs.State, bits)
		// echo "verifier= [{$this->verifier}]\n\n";
		// echo "salt=     [{$this->salt}]\n\n";
		fmt.Printf("salt=     [%s]\n", gs.Salt.HexString())
		// echo "Nhex=     [{$this->Nhex}]\n\n";
		// echo "g=        [{$this->g}]\n\n";
		fmt.Printf("khex=     [%s]\n", gs.Xk.HexString())
		fmt.Printf("vhex=     [%s]\n", gs.Xv.HexString())
		fmt.Printf("key=      [%s]\n", gs.Key_s)
		fmt.Printf("bhex=     [%s]\n", gs.Xb.HexString())
		fmt.Printf("Bhex=     [%s]\n", gs.XB.HexString())
	}
}

/*
	echo "Simulated Client\n\n";
	echo "ST/bits=  [{$this->ST}/{$this->bits}]\n\n";
	echo "ahex=     [{$this->ahex}]\n\n";
	echo "Ahex=     [{$this->Ahex}]\n\n";
*/
func (gs *GoSrp) TestDump2() {
	if db8 {
		fmt.Printf("Simulated Client\n\n")
		fmt.Printf("ST/bits=  [%d/%d]\n\n", gs.State, bits)
		fmt.Printf("ahex=     [%s]\n", gs.Xa.HexString())
		fmt.Printf("Ahex=     [%s]\n", gs.XA.HexString())
		fmt.Printf("M1_s=     [%s] (client M)\n", gs.XM1_s)
	}
}

/*
	public function dumpVars3() {
		echo "ST/bits=  [{$this->ST}/{$this->bits}]\n\n";
		echo "Ahex=     [{$this->Ahex}]\n\n";
		echo "Shex=     [{$this->Shex}]\n\n";
		echo "M=        [{$this->M}]\n\n";
		echo "HAMK=     [{$this->HAMK}]\n\n";
		echo "key=      [{$this->key}]\n\n";
	}
*/
func (gs *GoSrp) TestDump3() {
	if db8 {
		fmt.Printf("ST/bits=  [%d/%d]\n\n", gs.State, bits)
		fmt.Printf("Ahex=     [%s]\n", gs.XA.HexString())
		fmt.Printf("Shex=     [%s]\n", gs.XS.HexString())
		fmt.Printf("key=      [%s]\n", gs.Key_s)
		fmt.Printf("--\n")
		fmt.Printf("uhex=     [%s]\n", gs.Xu.HexString())
		fmt.Printf("vhex=     [%s]\n", gs.Xv.HexString())
		fmt.Printf("avuhex=   [%s]\n", gs.Xavu.HexString())
	}
}

func (gs *GoSrp) TestDump4() {
	if db8 {
		fmt.Printf("M1=       [%s] (Server M)\n", gs.XM1_s)
		fmt.Printf("M2=       [%s] (Server M)\n", gs.XM2_s)
		fmt.Printf("HAMK=     [%s]\n", gs.XHAMK_s)
		fmt.Printf("Auth =    [%v]\n", gs.Auth)
	}
}

func (gs *GoSrp) FixRandom(rval string) {
	if dbTestingMode {
		gs.fixRandomFlag = true
		gs.randomStr = rval
	}
}

const db8 = false           // dumps bunches out stuff to output (log) for testing, do not compile production version with this true.
const dbDumpKeyToLog = true // dumps key to stderr, do not compile production version with this true.
const dbTestingMode = true  // allows fixing of random number to a constant for testing, do not compile production version with this true.
const dbCipher = false      // output message that we reached random number generat, file line.  Mostly harmless.

/* vim: set noai ts=4 sw=4: */
